/// This class holds all the android keystore adjacent data and handles it, if the project isn't
/// compiled for android, nothing should be compiled.
/// Be warned that this also includes a global static reference to the DVM which is loaded via the
/// C foreign function JNI_OnLoad() which is called when android calls System.loadLibrary() function
/// some particular use cases, such as flutter, might be required to manually call
/// [JNI_OnLoad()](https://docs.oracle.com/javase/8/docs/technotes/guides/jni/spec/invocation.html#JNJI_OnLoad)
#[cfg(target_os = "android")]
pub(crate) mod android_keystore {
    use jni::objects::{JByteArray, JObject, JString, JValue};
    use jni::sys::jint;
    use jni::{errors, JNIEnv, JavaVM};
    use log::info;
    use once_cell::sync::OnceCell;

    const ANDROID_STORE: &str = "AndroidKeyStore";
    enum KeyMode {
        UnwrapMode = 4,
        WrapMode = 3,
        DecryptMode = 2,
        EncryptMode = 1,
    }

    /// Android applications work through a DVM, this Dalvik Virtual Machine is in turn a type of
    /// JVM (ie reads bytecode), which is unique per application, as it is a JVM implementation, it
    /// means the JNI_OnLoad() will load up upon the native library being loaded via
    /// [System.loadLibrary](https://developer.android.com/reference/java/lang/System#loadLibrary(java.lang.String))
    /// This singular pointer is then kept inside of this once cell, which becomes a 'static ref.
    pub(crate) static CELL_DVM: OnceCell<JavaVM> = OnceCell::new();

    /// Gets an [Android Keystore](https://developer.android.com/reference/java/security/KeyStore)
    /// instance through calls to the DVM, which in turn connect to the android.security.keystore
    /// native service.
    /// Currently, the keystore name is not configurable.
    fn get_keystore<'a, 'b>(env: &'b mut JNIEnv<'a>) -> JObject<'a> {
        let jclass_keystore = env.find_class("java/security/KeyStore").unwrap();
        let android_key_store = env.new_string(ANDROID_STORE.clone()).unwrap();

        let keystore_name =
            JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&android_key_store));

        let get_instance_call = env
            .call_static_method(
                jclass_keystore,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
                &[keystore_name],
            )
            .expect("Can't get instance");

        let keystore_jobject = JObject::try_from(get_instance_call)
            .expect("Cannot turn JValueOwned of getInstance to Jobject");

        let binding = JObject::null();
        let load_store_param = JValue::from(&binding);

        env.call_method(
            &keystore_jobject,
            "load",
            "(Ljava/security/KeyStore$LoadStoreParameter;)V",
            &[load_store_param],
        )
        .expect("Can't load instance of keystore");

        keystore_jobject
    }

    /// Gets a key off a keystore instance, this instanciates a keystore for this express purpose.
    fn get_key<'a, 'b>(key_name: String, env: &'b mut JNIEnv<'a>) -> JObject<'a> {
        info!("get_key {}", key_name.clone());
        let keystore = get_keystore(env);

        let key_name = env.new_string(key_name.clone()).unwrap();
        info!("key_name success");

        let key_name = JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&key_name));

        let binding = JObject::null();
        let protection_param = JValue::from(&binding);
        info!("protection_param success");

        // Call the getEntry function
        let keystore_entry = env.call_method(
            &keystore,
            "getEntry",
            "(\
                                               Ljava/lang/String;\
                                               Ljava/security/KeyStore\
                                               $ProtectionParameter;\
                                               )\
                                               Ljava/security/KeyStore$Entry;",
            &[key_name, protection_param],
        );
        info!("getEntry success");

        let keystore_entry = keystore_entry.expect("Can't find key");
        info!("keystore_entry success");

        // We gotta assign, ie cast it so time to use is_assignable_from() aka IsAssignableFrom()
        let keystore_entry = JObject::try_from(keystore_entry)
            .expect("Cannot turn JValueOwned of getInstance to Jobject");
        info!("keystore_entry success");

        keystore_entry
    }

    /// Gets a secret key off a keystore instance, this instanciates a keystore for this express
    /// purpose.
    fn get_secret_key<'a, 'b>(key_name: String, env: &'b mut JNIEnv<'a>) -> JObject<'a> {
        info!("get_secret_key {}", key_name.clone());

        let key_jobject = get_key(key_name, env);
        let entry_secretkey_jvalueowned = env.call_method(
            key_jobject,
            "getSecretKey",
            "()Ljavax/crypto/SecretKey;",
            &[],
        );

        JObject::try_from(entry_secretkey_jvalueowned.unwrap()).unwrap()
    }

    /// Gets a [javax.cipher](https://developer.android.com/reference/javax/crypto/Cipher) instance,
    /// this is used for cryptographic operations using the [Android Keystore](https://developer.android.com/reference/java/security/KeyStore)
    /// as the keys cannot be extracted from the HSM.
    fn get_cipher_instance<'a, 'b>(env: &'b mut JNIEnv<'a>) -> JObject<'a> {
        let jclass_cipher = env.find_class("javax/crypto/Cipher").unwrap();

        let transformation = env.new_string("AES/CBC/PKCS7Padding").unwrap();
        let jvalue_transformation =
            JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&transformation));

        let cipher_getinstance_jvalue = env
            .call_static_method(
                jclass_cipher,
                "getInstance",
                "(Ljava/lang/String;)Ljavax/crypto/Cipher;",
                &[jvalue_transformation],
            )
            .unwrap();

        JObject::try_from(cipher_getinstance_jvalue)
            .expect("Cannot turn JValueOwned of getInstance to Jobject")
    }

    /// Attempts to fetch the given key and then encrypt an arbitrary vector, for now this function
    /// only supports operations done with AES keys using CBC block and PKCS7 padding.
    pub fn encrypt(key_name: String, data: Vec<u8>) -> Result<Vec<u8>, errors::Error> {
        info!("Starting Encrypt");

        let env = &mut CELL_DVM
            .get()
            .expect("No JVM")
            .get_env()
            .expect("No JNIEnv");

        let jclass_outputstream = env.find_class("java/io/ByteArrayOutputStream")?;

        let jobject_outputstream = env.new_object(jclass_outputstream, "()V", &[])?;

        let cipher_jobject = get_cipher_instance(env);
        info!("cipher_jobject");

        let entry_secret_key_jobject = get_secret_key(key_name, env);
        info!("entry_secret_key_jobject");

        let entry_jvalue = JValue::from(&entry_secret_key_jobject);
        info!("entry_jvalue");

        let key_purpose_jint_decrypt: jint = KeyMode::EncryptMode as i32;
        let key_purpose_jobject = JValue::from(key_purpose_jint_decrypt);
        info!("key_purpose_jobject");

        let _cipher_init_jvalue = env.call_method(
            &cipher_jobject,
            "init",
            "(ILjava/security/Key;)V",
            &[key_purpose_jobject, entry_jvalue],
        );
        info!("_cipher_init_jvalue");

        let datajbyte_array = env.byte_array_from_slice(&*data)?;
        let jbytes = JValue::from(&datajbyte_array);

        let dofinal_jvalue = env.call_method(&cipher_jobject, "doFinal", "([B)[B", &[jbytes])?;

        let encrypted_bytes_jobject = JObject::try_from(dofinal_jvalue)
            .expect("Cannot turn JValueOwned of getInstance to Jobject");
        let encrypted_bytes_jarray = JByteArray::try_from(encrypted_bytes_jobject).unwrap();
        let encrypted_bytes_jvalue = JValue::from(&encrypted_bytes_jarray);

        //IV sizing
        let cipher_iv_jarray = env.call_method(cipher_jobject, "getIV", "()[B", &[]);
        info!("cipher_iv_jarray!");

        let cipher_iv_jobject = JObject::try_from(cipher_iv_jarray?)
            .expect("Cannot turn JValueOwned of getInstance to Jobject");
        let cipher_jarray = JByteArray::from(cipher_iv_jobject);

        let cipher_iv_size = env.get_array_length(&cipher_jarray);

        let cipher_iv_jvalue = JValue::from(&cipher_jarray);

        let cipher_iv_size_jint: jint = cipher_iv_size?;
        let cipher_iv_size_jvalue = JValue::from(cipher_iv_size_jint);

        //TODO Write stack, need to move into a function
        let _write_iv_size = env.call_method(
            &jobject_outputstream,
            "write",
            "(I)V",
            &[cipher_iv_size_jvalue],
        );

        let _write_iv =
            env.call_method(&jobject_outputstream, "write", "([B)V", &[cipher_iv_jvalue]);

        let _write_iv =
            env.call_method(&jobject_outputstream, "write", "(I)V", &[cipher_iv_jvalue]);

        let _write_encrypted_bytes = env.call_method(
            &jobject_outputstream,
            "write",
            "([B)V",
            &[encrypted_bytes_jvalue],
        );
        info!("_write_encrypted_bytes!");

        let tobytearray_call =
            env.call_method(&jobject_outputstream, "toByteArray", "()[B", &[])?;
        let tobytearray_jobject = JObject::try_from(tobytearray_call)
            .expect("Cannot turn JValueOwned of toByteArray to JObject");
        let encrypted_array = JByteArray::try_from(tobytearray_jobject).unwrap();

        let _close_outputstream = env.call_method(&jobject_outputstream, "close", "()V", &[]);

        let encrypted_bytes_jvalue = env.convert_byte_array(&encrypted_array);

        encrypted_bytes_jvalue
    }

    /// Attempts to fetch the given key and then decrypt an arbitrary vector, for now this function
    /// only supports operations done with AES keys using CBC block and PKCS7 padding.
    pub fn decrypt(key_name: String, data: Vec<u8>) -> Result<Vec<u8>, errors::Error> {
        let env = &mut CELL_DVM
            .get()
            .expect("No JVM")
            .get_env()
            .expect("No JNIEnv");

        let (iv, encrypted_data) = data.split_at(1).1.split_at(data[0] as usize);

        let entry_secret_key_jobject = get_secret_key(key_name, env);

        let entry_jvalue = JValue::from(&entry_secret_key_jobject);

        let key_purpose_jint_decrypt: jint = KeyMode::DecryptMode as i32; //Decrypt
        let key_purpose_jobject = JValue::from(key_purpose_jint_decrypt);

        let cipher_jobject = get_cipher_instance(env);

        let iv = env.byte_array_from_slice(iv);
        let iv = iv.unwrap();
        let iv_jvalue = JValue::from(&iv);
        let algorithmparameterspec_jclass = env.find_class("javax/crypto/spec/IvParameterSpec")?;
        let algorithmparameterspec_jobject =
            env.new_object(algorithmparameterspec_jclass, "([B)V", &[iv_jvalue]);
        let algorithmparameterspec_jobject = algorithmparameterspec_jobject.unwrap();
        let algorithmparameterspec_jvalue = JValue::from(&algorithmparameterspec_jobject);

        let _cipher_init_jvalue = env.call_method(
            &cipher_jobject,
            "init",
            "(ILjava/security/Key;Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[
                key_purpose_jobject,
                entry_jvalue,
                algorithmparameterspec_jvalue,
            ],
        );

        let encrypted_data = env.byte_array_from_slice(encrypted_data);
        let encrypted_data = encrypted_data.unwrap();
        let encrypted_data_jvalue = JValue::from(&encrypted_data);

        let bytearrayinputstream_jclass = env.find_class("java/io/ByteArrayInputStream").unwrap();
        let bytearrayinputstream_jobject = env.new_object(
            bytearrayinputstream_jclass,
            "([B)V",
            &[encrypted_data_jvalue],
        );

        let bytearrayinputstream_jobject = bytearrayinputstream_jobject.unwrap();

        let readbytes_jobject =
            env.call_method(&bytearrayinputstream_jobject, "readAllBytes", "()[B", &[]);

        let readbytes_jobject = readbytes_jobject.unwrap();

        let readbytes_jvalue = JValue::from(&readbytes_jobject);

        let dofinal_jobject =
            env.call_method(&cipher_jobject, "doFinal", "([B)[B", &[readbytes_jvalue]);

        let dofinal_jvalue = dofinal_jobject.unwrap();
        let dofinal_jobject = JObject::try_from(dofinal_jvalue)
            .expect("Cannot turn JValueOwned of toByteArray to JObject");
        let decrypted_array = JByteArray::try_from(dofinal_jobject).unwrap();

        env.convert_byte_array(&decrypted_array)
    }

    /// Attempts to create a key with the given name and put it in the AndroidKeyStore, for now this
    /// key is made as an AES key.
    pub fn create_key_encrypt(key_name: String) {
        let env = &mut CELL_DVM
            .get()
            .expect("No JVM")
            .get_env()
            .expect("No JNIEnv");

        let provider = env.new_string(ANDROID_STORE.clone()).unwrap();
        let provider = JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&provider));

        let jclass_keypairgenerator = env.find_class("javax/crypto/KeyGenerator").unwrap();

        let jstring_aes = env.new_string("AES").unwrap();
        let jvalue_aes = JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&jstring_aes));

        let keygenerator_instance_jvalue = env
            .call_static_method(
                jclass_keypairgenerator,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
                &[jvalue_aes, provider],
            )
            .unwrap();

        //With the keygenerator instanciated (see above) we need to call KeyGenParameterSpec and then .Builder(String, Purposes)
        let jclass_keygen_parameterspec = env
            .find_class("android/security/keystore/KeyGenParameterSpec$Builder")
            .unwrap();

        let key_name_jstring = env.new_string(key_name.clone()).unwrap();
        let key_name_jobject =
            JValue::from(<JString<'_> as AsRef<JObject>>::as_ref(&key_name_jstring));

        let key_purpose_jint: jint = KeyMode::EncryptMode as i32 | KeyMode::DecryptMode as i32;
        let key_purpose_jobject = JValue::from(key_purpose_jint);

        let builder_jvalue = env
            .new_object(
                jclass_keygen_parameterspec,
                "(Ljava/lang/String;I)V",
                &[key_name_jobject, key_purpose_jobject],
            )
            .unwrap();

        let builder_jobject = JObject::try_from(builder_jvalue)
            .expect("Cannot turn JValueOwned of KeyPairGenerator.Builder to Jobject");

        // Secret keys require setting the block modes (String...) & encryption paddings(String...)

        // setBlockModes
        let cbc_block_jstring = env.new_string("CBC").unwrap();
        let string_class = env.find_class("java/lang/String").unwrap();
        let block_jarray = env
            .new_object_array(1, string_class, cbc_block_jstring)
            .unwrap();
        let blocks = JValue::from(&block_jarray);

        let builder_jvalue = env
            .call_method(
                builder_jobject,
                "setBlockModes",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[blocks],
            )
            .unwrap();

        let builder_jobject = JObject::try_from(builder_jvalue);

        let builder_jobject = builder_jobject.unwrap();

        // setEncryptionPaddings
        let pkcs7_padding_jstring = env.new_string("PKCS7Padding").unwrap();
        let string_class = env.find_class("java/lang/String").unwrap();
        let padding_array = env
            .new_object_array(1, string_class, pkcs7_padding_jstring)
            .unwrap();
        let paddings = JValue::from(&padding_array);

        let builder_jvalue = env
            .call_method(
                builder_jobject,
                "setEncryptionPaddings",
                "([Ljava/lang/String;)Landroid/security/keystore/KeyGenParameterSpec$Builder;",
                &[paddings],
            )
            .unwrap();

        let builder_jobject = JObject::try_from(builder_jvalue);

        let builder_jobject = builder_jobject.unwrap();

        // Done, now build
        let builder_jvalue = env
            .call_method(
                builder_jobject,
                "build",
                "()Landroid/security/keystore/KeyGenParameterSpec;",
                &[],
            )
            .unwrap();
        let builder_jobject = JObject::try_from(builder_jvalue).unwrap();

        let parameterspec_jvalue = JValue::from(&builder_jobject);

        let keygenerator_instance_jobject =
            JObject::try_from(keygenerator_instance_jvalue).unwrap();

        // No return values here; you can check for errors but there is nothing to unwrap either way
        env.call_method(
            &keygenerator_instance_jobject,
            "init",
            "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            &[parameterspec_jvalue],
        )
        .unwrap();

        env.call_method(
            keygenerator_instance_jobject,
            "generateKey",
            "()Ljavax/crypto/SecretKey;",
            &[],
        )
        .unwrap();
    }
}
