#pragma once
#pragma warning(disable: 4200)

typedef void MonoArrayType;
typedef void MonoGenericParam;
typedef void MonoGenericClass;
typedef uint8_t guint8;
typedef uint16_t guint16;
typedef uint guint, guint32;
typedef enum {
    TYPE_END = 0x00,       /* End of List */
    TYPE_VOID = 0x01,
    TYPE_BOOLEAN = 0x02,
    TYPE_CHAR = 0x03,
    TYPE_I1 = 0x04,
    TYPE_U1 = 0x05,
    TYPE_I2 = 0x06,
    TYPE_U2 = 0x07,
    TYPE_I4 = 0x08,
    TYPE_U4 = 0x09,
    TYPE_I8 = 0x0a,
    TYPE_U8 = 0x0b,
    TYPE_R4 = 0x0c,
    TYPE_R8 = 0x0d,
    TYPE_STRING = 0x0e,
    TYPE_PTR = 0x0f,       /* arg: <type> token */
    TYPE_BYREF = 0x10,       /* arg: <type> token */
    TYPE_VALUETYPE = 0x11,       /* arg: <type> token */
    TYPE_CLASS = 0x12,       /* arg: <type> token */
    TYPE_VAR = 0x13,	   /* number */
    TYPE_ARRAY = 0x14,       /* type, rank, boundsCount, bound1, loCount, lo1 */
    TYPE_GENERICINST = 0x15,	   /* <type> <type-arg-count> <type-1> \x{2026} <type-n> */
    TYPE_TYPEDBYREF = 0x16,
    TYPE_I = 0x18,
    TYPE_U = 0x19,
    TYPE_FNPTR = 0x1b,	      /* arg: full method signature */
    TYPE_OBJECT = 0x1c,
    TYPE_SZARRAY = 0x1d,       /* 0-based one-dim-array */
    TYPE_MVAR = 0x1e,       /* number */
    TYPE_CMOD_REQD = 0x1f,       /* arg: typedef or typeref token */
    TYPE_CMOD_OPT = 0x20,       /* optional arg: typedef or typref token */
    TYPE_INTERNAL = 0x21,       /* CLR internal type */

    TYPE_MODIFIER = 0x40,       /* Or with the following types */
    TYPE_SENTINEL = 0x41,       /* Sentinel for varargs method signature */
    TYPE_PINNED = 0x45,       /* Local var that points to pinned object */

    TYPE_ENUM = 0x55        /* an enumeration */
} MonoTypeEnum;

struct MonoType {
    union {
        struct MonoClass* klass; /* for VALUETYPE and CLASS */
        MonoType* type;   /* for PTR */
        MonoArrayType* array; /* for ARRAY */
        struct MonoMethodSignature* method;
        MonoGenericParam* generic_param; /* for VAR and MVAR */
        MonoGenericClass* generic_class; /* for GENERICINST */
    } data;
    unsigned int attrs : 16; /* param attributes or field flags */
    MonoTypeEnum type : 8;
    unsigned int has_cmods : 1;
    unsigned int byref : 1;
    unsigned int pinned : 1;  /* valid when included in a local var signature */
};

struct MonoClass {
	/* element class for arrays and enum basetype for enums */
	MonoClass* element_class;
	/* used for subtype checks */
	MonoClass* cast_class;

	/* for fast subtype checks */
	MonoClass** supertypes;
	guint16     idepth;

	/* array dimension */
	guint8     rank;

	/* One of the values from MonoTypeKind */
	guint8     class_kind;

	int        instance_size; /* object instance size */

	guint inited : 1;

	/* A class contains static and non static data. Static data can be
	 * of the same type as the class itselfs, but it does not influence
	 * the instance size of the class. To avoid cyclic calls to
	 * class_init_internal (from class_instance_size ()) we first
	 * initialise all non static fields. After that we set size_inited
	 * to 1, because we know the instance size now. After that we
	 * initialise all static fields.
	 */
	 /* ALL BITFIELDS SHOULD BE WRITTEN WHILE HOLDING THE LOADER LOCK */
	guint size_inited : 1;
	guint valuetype : 1; /* derives from System.ValueType */
	guint enumtype : 1; /* derives from System.Enum */
	guint blittable : 1; /* class is blittable */
	guint unicode : 1; /* class uses unicode char when marshalled */
	guint wastypebuilder : 1; /* class was created at runtime from a TypeBuilder */
	guint is_array_special_interface : 1; /* gtd or ginst of once of the magic interfaces that arrays implement */
	guint is_byreflike : 1; /* class is a valuetype and has System.Runtime.CompilerServices.IsByRefLikeAttribute */

	/* next byte */
	guint8 min_align;

	/* next byte */
	guint packing_size : 4;
	guint ghcimpl : 1; /* class has its own GetHashCode impl */
	guint has_finalize : 1; /* class has its own Finalize impl */
#ifndef DISABLE_REMOTING
	guint marshalbyref : 1; /* class is a MarshalByRefObject */
	guint contextbound : 1; /* class is a ContextBoundObject */
#endif
	/* next byte */
	guint delegate        : 1; /* class is a Delegate */
	guint gc_descr_inited : 1; /* gc_descr is initialized */
	guint has_cctor : 1; /* class has a cctor */
	guint has_references : 1; /* it has GC-tracked references in the instance */
	guint has_static_refs : 1; /* it has static fields that are GC-tracked */
	guint no_special_static_fields : 1; /* has no thread/context static fields */
	/* directly or indirectly derives from ComImport attributed class.
	 * this means we need to create a proxy for instances of this class
	 * for COM Interop. set this flag on loading so all we need is a quick check
	 * during object creation rather than having to traverse supertypes
	 */
	guint is_com_object : 1;
	guint nested_classes_inited : 1; /* Whenever nested_class is initialized */

	/* next byte*/
	guint interfaces_inited : 1; /* interfaces is initialized */
	guint simd_type : 1; /* class is a simd intrinsic type */
	guint has_finalize_inited : 1; /* has_finalize is initialized */
	guint fields_inited : 1; /* setup_fields () has finished */
	guint has_failure : 1; /* See class_get_exception_data () for a MonoErrorBoxed with the details */
	guint has_weak_fields : 1; /* class has weak reference fields */
	guint has_dim_conflicts : 1; /* Class has conflicting default interface methods */

	void* reserved;
	MonoClass* parent;
	MonoClass* nested_in;

	void* image;
	const char* name;
	const char* name_space;

	guint32    type_token;
	int        vtable_size; /* number of slots */

	guint16     interface_count;
	guint32     interface_id;        /* unique inderface id (for interfaces) */
	guint32     max_interface_id;

	guint16     interface_offsets_count;
	MonoClass** interfaces_packed;
	guint16* interface_offsets_packed;
	guint8* interface_bitmap;

	MonoClass** interfaces;

	/*
	 * Field information: Type and location from object base
	 */
	void* fields;

	struct MonoMethod** methods;

	/* used as the type of the this argument and when passing the arg by value */
	MonoType this_arg;
	MonoType _byval_arg;
};

struct MonoMethodSignature {
    MonoType ret;
#ifdef SMALL_CONFIG
    uint8_t        param_count;
    int8_t         sentinelpos;
    unsigned int  generic_param_count : 5;
#else
    uint16_t       param_count;
    int16_t        sentinelpos;
    unsigned int  generic_param_count : 16;
#endif
    unsigned int  call_convention : 6;
    unsigned int  hasthis : 1;
    unsigned int  explicit_this : 1;
    unsigned int  pinvoke : 1;
    unsigned int  is_inflated : 1;
    unsigned int  has_type_parameters : 1;
    MonoType* params[0];
};

struct MonoMethod {
    uint16_t flags;  /* method flags */
    uint16_t iflags; /* method implementation flags */
    uint32_t token;
    MonoClass* klass;
    MonoMethodSignature* signature;
    const char* name;
    unsigned int inline_info : 1;
    unsigned int inline_failure : 1;
    unsigned int wrapper_type : 5;
    unsigned int string_ctor : 1;
    unsigned int save_lmf : 1;
    unsigned int dynamic : 1; /* created & destroyed during runtime */
    unsigned int is_generic : 1; /* whenever this is a generic method definition */
    unsigned int is_inflated : 1; /* whether we're a MonoMethodInflated */
    unsigned int skip_visibility : 1; /* whenever to skip JIT visibility checks */
    unsigned int verification_success : 1; /* whether this method has been verified successfully.*/
    unsigned int is_mb_open : 1;		/* This is the fully open instantiation of a generic method_builder. Worse than is_tb_open, but it's temporary */
    signed int slot : 17;
};

struct MonoObject {
	void* vtable;
	void* synchronisation;
};

struct MonoString {
	MonoObject object;
	int32_t length;
	wchar_t chars[0];
};

typedef struct _MonoImage MonoImage;
typedef struct _MonoAssembly MonoAssembly;

typedef enum {
	IMAGE_OK,
	IMAGE_ERROR_ERRNO,
	IMAGE_MISSING_ASSEMBLYREF,
	IMAGE_IMAGE_INVALID
} MonoImageOpenStatus;


#define GetMethod(inst, name)   name = (decltype(name))GetProcAddress(inst, "mono_"#name)
#define GetMethodOri(inst, name)   name = (decltype(name))GetProcAddress(inst, #name)
#define GetMethodAddress(inst, name, offset) name = (decltype(name))(reinterpret_cast<char*>(inst)+offset)
#define capture(method, result, name) try_capture(mono, method, result, #name, name)
#define capture_ex(method, result, target_name, name) try_capture(mono, method, result, target_name, name)

class Mono {
    bool initialized = false;
public:
    bool IsInitialized()const { return initialized; }
    const char* (*method_get_name)(MonoMethod* method);
    const char* (*method_full_name)(MonoMethod* method, bool signature);
    void* (*compile_method)(MonoMethod* method);
    MonoImage* (*get_corlib)();
    MonoClass* (*class_from_name)(void* image, const char* ns, const char* name);
    MonoMethod* (*object_get_virtual_method)(void* object, MonoMethod* method);
    MonoMethod* (*get_inflated_method)(MonoMethod* method);
    MonoClass* (*class_bind_generic_parameters)(MonoClass*, int, MonoType**, bool);
    MonoType* (*class_get_type)(MonoClass*);
    MonoClass* (*object_get_class)(MonoObject* obj);
    MonoMethod* (*class_get_method_from_name)(MonoClass*, const char*, int);
    MonoAssembly* (*image_open)(const char* name, MonoImageOpenStatus* status);
    MonoObject* (*runtime_invoke)(MonoMethod* method, void* obj, void** params, MonoObject** exc);
    MonoMethod* (*get_method_full)(MonoImage* image, uint32_t token, MonoClass* klass);
    MonoMethod* (*unity_mono_reflection_method_get_method)(void* mcf);
    MonoMethod* (*class_get_methods)(MonoClass* klass, void* iter);
    MonoMethod* (*class_get_method_from_name_flags)(MonoClass* klass, void* iter, uint32_t token, uint32_t a4);
    MonoMethod* (*jit_info_get_method)(void* ji);
    void* (*jit_info_get_code_start)(void* ji);
    bool Initialize(const char* dll) {
        auto mono = GetModuleHandleA(dll);
        if (mono != nullptr) {
            if (false == initialized) {
                GetMethod(mono, compile_method);
                GetMethod(mono, method_get_name);
                GetMethod(mono, method_full_name);
                GetMethod(mono, object_get_class);
                GetMethod(mono, class_get_method_from_name);
                //GetMethod(mono, method_get_class);
                GetMethod(mono, get_corlib);
                GetMethod(mono, class_from_name);
                GetMethod(mono, object_get_virtual_method);
                //GetMethod(mono, class_get_method_from_name_flags);
                GetMethod(mono, get_inflated_method);
                GetMethod(mono, class_bind_generic_parameters);
                GetMethod(mono, class_get_type);
                GetMethod(mono, image_open);
                GetMethod(mono, get_method_full);
                GetMethodOri(mono, unity_mono_reflection_method_get_method);
                GetMethod(mono, class_get_methods);
                GetMethod(mono, jit_info_get_method);
                GetMethod(mono, class_get_method_from_name_flags);
                GetMethod(mono, runtime_invoke);
                GetMethod(mono, jit_info_get_code_start);
                initialized = true;
            }
        }
        return initialized;
    }
};

template<typename Func>
inline void try_capture(Mono& mono, MonoMethod* method, void* address, std::string thismethodname, Func thismethod) {
    replace_inline(thismethodname, "::", ":");
    replace_inline(thismethodname, "$", ".");
    std::string fullname = mono.method_full_name(method, false);
    if (fullname.substr(0, thismethodname.size()) == thismethodname && !hookapi::is_hooked(address)) {
        hookapi::hook_unsafe(address, thismethod);
        //od("====", thismethodname, "hooked====");
    }
}