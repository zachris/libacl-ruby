require 'rubygems'
gem 'ffi', '>= 0.5.0'
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


#FFI Posix ACL tested on linux and definitely not working on darwin.
module LibACL
  extend NiceFFI::Library
  #ffi_lib 'libacl'


	if FFI::Platform::IS_LINUX
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
	
	end #is linux

	  	  		  		  		  		  		  		  		  		  		  		  		  		  		  	  	  			  			  			  			  			  			  	  	  			  			    

  class ACL < NiceFFI::OpaqueStruct
  	include Enumerable
  #Create struct capable of holding num entries
  def self.init(num=10)
    LibACL::acl_init(num)
  end

    def self.release(ptr)
      acl_free(ptr)
    end

    #Construct from file, using mode :access or :default
    def self.from_file(path, mode=:access)
      LibACL::acl_get_file(path,mode)
    end
    
    def self.default(dir)
      assert File.directory? dir
      self.from_file(dir,:default)
    end

    #Construct from text
    def self.from_text(text)
      LibACL::acl_from_text(text)
    end

    #Create a copy of acl. 
    def clone
      LibACL::acl_dup(self)
    end

    def valid?
      LibACL::acl_valid(self)==0
    end


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
      entry_p = FFI::MemoryPointer.new :pointer
      #acl_p = self.pointer
      ret= LibACL::acl_create_entry(self, entry_p )
      raise "Can't create entry" if ret == -1

      
      #test this case...
#      #in case of reallocation
#      if acl_p.pointer.address != self.pointer.address
#        self.pointer=acl_p
#      end
      Entry.new entry_p.read_pointer
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
      while (having>0)
        entry=Entry.new ptr.read_pointer
        blk.call entry
        having = LibACL::acl_get_entry(self, :next_entry, ptr)
      end
      
      raise "Error getting entry" if having == -1
    end

    #methods using each implementation

    def user_obj
      entry_find :user_obj
    end

    def group_obj
      entry_find :group_obj
    end

    def other
      entry_find :other
    end

    def mask
      entry_find :mask
    end


    def entry_find(tag)
      find do |entry| 	
        entry.tag_type==tag
      end
    end

  end



  class Entry < NiceFFI::OpaqueStruct
        def self.release(ptr)
          acl_free(ptr)
        end

    #replace this entry with source
    def replace(source)
      LibACL::acl_copy_entry(self,source)
    end


    def permset
      ptr = FFI::MemoryPointer.new :pointer
      ret = LibACL::acl_get_permset(self, ptr)
      raise "Error" if ret!=0
      Permset.new ptr.read_pointer
    end

    #def permset=
    #
    #end

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

    def == (other)
      permset == other.permset and
        tag_type == other.tag_type and
        qualifier == other.qualifier
    end
    
    def to_s
     # tag=tag_type.to_s.sub("_obj","")
      "#{tag_type}:#{qualifier}:#{permset}"
    end

  end
  
  class Permset<NiceFFI::OpaqueStruct
    @@perm_t=LibACL::find_type(:acl_perm)
  
    def clear
      LibACL::acl_clear_perms(self)
    end
	
    def add(perm)
      LibACL::acl_add_perm(self,@@perm_t[perm])
    end
	
    def delete(perm)
      LibACL::acl_delete_perm(self,@@perm_t[perm])
    end
	
    def is_set?(perm)
      LibACL::acl_get_perm(self, @@perm_t[perm]) >0
    end

    #a linux hack/shortcut
    def to_i
      pointer.read_int
    end
	
    def == (other)
      to_i == other.to_i
    end


    def read?
      is_set? :read
    end
	
    def write?
      is_set? :write
    end
	
    def execute?
      is_set? :execute
    end
	
    def to_s
      ret=""
      read? ? ret << "r" : ret << "-"
      write? ? ret << "w" : ret << "-"
      execute? ? ret << "x" : ret << "-"
      ret
    end
  
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
  attach_function 'acl_add_perm',[:pointer,:acl_perm],:int
  
  #  extern int acl_calc_mask(acl_t *acl_p);
  #  extern int acl_clear_perms(acl_permset_t permset_d);
  attach_function 'acl_clear_perms',[:pointer],:int
  
  #  extern int acl_delete_perm(acl_permset_t permset_d, acl_perm_t perm);
  attach_function 'acl_delete_perm',[:pointer, :acl_perm],:int
  
  #  extern int acl_get_permset(acl_entry_t entry_d, acl_permset_t *permset_p);
  attach_function 'acl_get_permset', [:pointer,:pointer],:int
  #  extern int acl_set_permset(acl_entry_t entry_d, acl_permset_t permset_d);

  
  #on linux
  if FFI::Platform::IS_LINUX
    attach_function 'acl_get_perm',[:pointer,:acl_perm],:int
  elsif FFI::Platform::IS_BSD
    attach_function 'acl_get_perm',:acl_get_perm_np,[:pointer,:acl_perm],:int
	end
  #on bsd/osx
  #attach_function 'acl_get_perm_np',[:pointer,:pointer],:int
  
  
  #  #Manipulate ACL entry tag type and qualifier */
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









