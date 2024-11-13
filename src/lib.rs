mod android_keystore;

#[cfg(target_os = "android")]
mod android {
    extern crate jni;

    use crate::android_keystore::android_keystore::CELL_DVM;
    use jni::objects::{JByteArray, JClass, JString};
    use jni::sys::{jint, JNI_VERSION_1_6};
    use jni::{JNIEnv, JavaVM};
    use log::info;
    use std::ffi::c_void;
    use jni::errors::Error;

    #[no_mangle]
    pub unsafe extern "C" fn JNI_OnLoad(jvm: JavaVM, _reserved: *mut c_void) -> jint {
        android_logger::init_once(
            android_logger::Config::default().with_max_level(::log::LevelFilter::Trace),
        );
        info!("Initialized logging");

        CELL_DVM.get_or_init(move || jvm);
        crate::android_keystore::android_keystore::create_key_encrypt("MainKey".to_string());
        info!("Stored JVM pointer");
        return JNI_VERSION_1_6;
    }

    #[no_mangle]
    pub unsafe extern "C" fn Java_com_tbc_keystoresuite_AndroidKeystore_encrypt<'a>(
        mut env: JNIEnv<'a>,
        _: JClass<'a>,
        clear_text: JByteArray<'a>,
    ) -> JByteArray<'a> {
        let clear_text = env.convert_byte_array(&clear_text).unwrap();
        info!("Clear text {:?}", clear_text.clone());
        let encrypted_bytes =
            crate::android_keystore::android_keystore::encrypt("MainKey".to_string(), clear_text);
        match &encrypted_bytes {
            Ok(bytes) => {info!("Success on encrypt {:?} ", bytes.clone())}
            Err(err) => {info!("Error {:?} ", err.to_string())}
        }
        let encrypted_bytes = env.byte_array_from_slice(&*encrypted_bytes.unwrap()).unwrap();
        return encrypted_bytes;
    }
    #[no_mangle]
    pub unsafe extern "C" fn Java_com_tbc_keystoresuite_AndroidKeystore_decrypt<'a>(
        mut env: JNIEnv<'a>,
        _: JClass<'a>,
        cypher_text: JByteArray<'a>,
    ) -> JByteArray<'a> {
        let cypher_text = env.convert_byte_array(&cypher_text).unwrap();
        info!("cypher text {:?}", cypher_text.clone());
        let clear_bytes =
            crate::android_keystore::android_keystore::decrypt("MainKey".to_string(), cypher_text);

        match &clear_bytes {
            Ok(bytes) => {info!("Success on encrypt {:?} ", bytes.clone())}
            Err(err) => {info!("Error {:?} ", err.to_string())}
        }

        let clear_bytes = env.byte_array_from_slice(&*clear_bytes.unwrap()).unwrap();
        return clear_bytes;
    }
}
