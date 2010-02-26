require 'rubygems'
gem 'ffi', '>= 0.5.0'
gem 'nice-ffi','>=0.3.0'
require 'ffi'
require 'nice-ffi'
require 'test/unit/assertions'
include Test::Unit::Assertions

#Types:
#
#typedef unsigned int		acl_type_t;
#typedef int			acl_tag_t;
#typedef unsigned int		acl_perm_t;
#
#typedef struct __acl_ext	*acl_t;
#typedef struct __acl_entry_ext	*acl_entry_t;
#typedef struct __acl_permset_ext *acl_permset_t;


#FFI Posix ACL (tested on linux)
module LibACL
  extend NiceFFI::Library
  ffi_lib 'libacl'


  # === Constants ===
  #23.2.2 acl_perm_t values
  enum :acl_perm, [
    :read, 0x04,
    :write, 0x02,
    :execute, 0x01]


  #23.2.5 acl_tag_t values
  enum :acl_tag, [
    :undefined_tag, 0x00,
    :user_obj, 0x01, #regular owner
    :user, 0x02,
    :group_obj, 0x04,
    :group, 0x08,
    :mask, 0x10,
    :other, 0x20]

  

  #23.3.6 acl_type_t values */
  enum :acl_type, [
    :access, 0x8000,
    :default, 0x4000]


  #23.2.7 ACL qualifier constants */
  #type :id_t
  ACL_UNDEFINED_ID	= -1


  #23.2.8 ACL Entry Constants */
  enum :acl_entry, [
    :first_entry,0,
    :next_entry,1]


  class ACL < NiceFFI::OpaqueStruct

    def self.release(ptr)
      acl_free(ptr)
    end


    def self.from_file(path, mode=:access)
      LibACL::acl_get_file(path,mode)
    end


    def valid?
      LibACL::acl_valid(self)!=0
    end

    #memory handling of returned strings?
    def to_text
      LibACL::acl_to_text(self, nil)
    end


    def set_file(path, mode=:access)
      assert valid?
      assert File.exists? path
      LibACL::acl_set_file(path, mode, self)
    end


    def set_default(dir)
      assert valid?
      assert File.directory? dir
      set_file(dir, :default)
    end

    
    def create_entry
      ptr = FFI::MemoryPointer.new :pointer
      ret= LibACL::acl_create_entry(self, ptr )
      raise "Can't create entry" if ret == -1

      Entry.new ptr.read_pointer
    end

    #I'm unsure of how memory is handled in this case
    #Test!
    def delete_entry(entry)
      ret = LibACL::acl_delete_entry(self,entry)
      raise "Can't delete #{entry}" if ret == -1
    end

    
    def each(&blk)
      ptr = FFI::MemoryPointer.new :pointer
      having = LibACL::acl_get_entry(self, :first_entry, ptr)
      while having>0
        entry=Entry.new ptr.read_pointer
        blk.call entry
        having = LibACL::acl_get_entry(self, :next_entry, ptr)
      end
      
      raise "Error getting entry" if having == -1
    end


  end



  #This class only lives inside an ACL, and the ACL handles it's lifecycle. 
  class Entry < NiceFFI::OpaqueStruct
    #I think the ACL handles memory allocation/deallocation...
    
#    def self.release(ptr)
#      acl_free(ptr)
#    end

    #replace this entry with other
    #that is - copy everything in other to this
    def replace_with(other)
      LibACL::acl_copy_entry(self,other)
    end


    def permset
      ptr = FFI::MemoryPointer.new :pointer
      ret = LibACL::acl_get_permset(self, ptr)
      raise "Error" if ret!=0
      Permset.new ptr.read_pointer
    end

#    def permset=
#
#    end

    def tag_type
      type= LibACL::find_type(:acl_tag)
      ptr = FFI::MemoryPointer.new type
      ret = LibACL::acl_get_tag_type(self, ptr)
      raise "Error" if ret !=0
      type[ptr.read_int]
    end

    def qualifier
      ptr = LibACL::acl_get_qualifier(self)
      if ptr.null?
       return nil
      else 
      	return ptr.read_int
      end
    end


  end

  class Permset<NiceFFI::OpaqueStruct

    
  end



  #=== ACL manipulation ===

  #arg: entries_nr to allocate
  attach_function 'acl_init',[:int],NiceFFI::TypedPointer( ACL )
  attach_function 'acl_dup', [:pointer],NiceFFI::TypedPointer( ACL )
  attach_function 'acl_free', [:pointer],:void
  attach_function 'acl_valid', [:pointer],:int


  #=== Entry manipulation ===

  #copy (dest, source): code
  attach_function 'acl_copy_entry',[:pointer, :pointer],:int

  #acl, entry*: code
  attach_function 'acl_create_entry',[:pointer, :pointer],:int
  attach_function 'acl_delete_entry',[:pointer, :pointer],:int

  #*acl, entry_id, *entry_p: having code
  attach_function 'acl_get_entry', [:pointer, :int, :pointer], :int

  #Manipulate ACL entry permissions */

  #  extern int acl_add_perm(acl_permset_t permset_d, acl_perm_t perm);
  #  extern int acl_calc_mask(acl_t *acl_p);
  #  extern int acl_clear_perms(acl_permset_t permset_d);
  #  extern int acl_delete_perm(acl_permset_t permset_d, acl_perm_t perm);
  #  extern int acl_get_permset(acl_entry_t entry_d, acl_permset_t *permset_p);
  attach_function 'acl_get_permset', [:pointer,:pointer],:int
  #  extern int acl_set_permset(acl_entry_t entry_d, acl_permset_t permset_d);
  #
  #  #Manipulate ACL entry tag type and qualifier */
  #
  #  extern void * acl_get_qualifier(acl_entry_t entry_d);
  attach_function 'acl_get_qualifier',[:pointer],:pointer
  #  extern int acl_get_tag_type(acl_entry_t entry_d, acl_tag_t *tag_type_p);
  attach_function 'acl_get_tag_type',[:pointer,:pointer],:int
  #  extern int acl_set_qualifier(acl_entry_t entry_d, const void *tag_qualifier_p);
  attach_function 'acl_set_qualifier',[:pointer,:pointer],:int
  #  extern int acl_set_tag_type(acl_entry_t entry_d, acl_tag_t tag_type);



  #=== Format translation ===

  #attach_function 'acl_copy_ext', [:inbuffer,:pointer,:ssize_t],:ssize_t
  #extern acl_t acl_copy_int(const void *buf_p);

  attach_function 'acl_from_text', [:string],NiceFFI::TypedPointer( ACL )
  attach_function 'acl_size',[:pointer],:ssize_t

  #second pointer is ssize_t *len_p
  attach_function 'acl_to_text',[:pointer,:pointer],:string

  #=== Object manipulation ===

  #extern int acl_delete_def_file(const char *path_p);
  #extern acl_t acl_get_fd(int fd);
  
  #path, type: new acl
  attach_function 'acl_get_file',[:string, :acl_type ],NiceFFI::TypedPointer( ACL )

  #extern int acl_set_fd(int fd, acl_t acl);

  #int acl_set_file(const char *path_p, acl_type_t type, acl_t acl);
  attach_function 'acl_set_file',[:string, :acl_type, :pointer],:int
  

end







x=LibACL::acl_from_text("user::rwx\nuser:xa:rw")
puts "Class: #{x.class} is valid? #{x.valid?}"


#z=ACL::ACL.new(x)

#puts x.methods
puts "Using instance method:"
x.each do |entry|
	puts "<each> Entry: #{entry}"
	puts "<each..> Tag_type: #{entry.tag_type}"
  puts "<each..> Qualifier: #{entry.qualifier}"
  puts "<each..> Permset: #{entry.permset}"
end	
puts "Acl to text: #{x.to_text}\n\n"

f= LibACL::ACL.from_file("/archive/files")
puts "/archive/files: \n#{f.to_text}"


