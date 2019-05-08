MKTME Key Service API
=====================
MKTME is a new key service type added to the Linux Kernel Key Service.

The MKTME Key Service type is available when CONFIG_X86_INTEL_MKTME is
turned on in Intel platforms that support the MKTME feature.

The MKTME Key Service type manages the allocation of hardware encryption
keys. Users can request an MKTME type key and then use that key to
encrypt memory with the encrypt_mprotect() system call.

Usage
-----
    When using the Kernel Key Service to request an *mktme* key,
    specify the *payload* as follows:

    type=
        *user*	User will supply the encryption key data. Use this
                type to directly program a hardware encryption key.

        *cpu*	User requests a CPU generated encryption key.
                The CPU generates and assigns an ephemeral key.

        *no-encrypt*
                 User requests that hardware does not encrypt
                 memory when this key is in use.

    algorithm=
        When type=user or type=cpu the algorithm field must be
        *aes-xts-128*

        When type=clear or type=no-encrypt the algorithm field
        must not be present in the payload.

    key=
        When type=user the user must supply a 128 bit encryption
        key as exactly 32 ASCII hexadecimal characters.

	When type=cpu the user may optionally supply 128 bits of
        entropy for the CPU generated encryption key in this field.
        It must be exactly 32 ASCII hexadecimal characters.

	When type=no-encrypt this key field must not be present
        in the payload.

    tweak=
	When type=user the user must supply a 128 bit tweak key
        as exactly 32 ASCII hexadecimal characters.

	When type=cpu the user may optionally supply 128 bits of
        entropy for the CPU generated tweak key in this field.
        It must be exactly 32 ASCII hexadecimal characters.

        When type=no-encrypt the tweak field must not be present
        in the payload.

ERRORS
------
    In addition to the Errors returned from the Kernel Key Service,
    add_key(2) or keyctl(1) commands, the MKTME Key Service type may
    return the following errors:

    EINVAL for any payload specification that does not match the
           MKTME type payload as defined above.

    EACCES for access denied. The MKTME key type uses capabilities
           to restrict the allocation of keys to privileged users.
           CAP_SYS_RESOURCE is required, but it will accept the
           broader capability of CAP_SYS_ADMIN. See capabilities(7).

    ENOKEY if a hardware key cannot be allocated. Additional error
           messages will describe the hardware programming errors.

EXAMPLES
--------
    Add a 'user' type key::

        char \*options_USER = "type=user
                               algorithm=aes-xts-128
                               key=12345678912345671234567891234567
                               tweak=12345678912345671234567891234567";

        key = add_key("mktme", "name", options_USER, strlen(options_USER),
                      KEY_SPEC_THREAD_KEYRING);

    Add a 'cpu' type key::

        char \*options_USER = "type=cpu algorithm=aes-xts-128";

        key = add_key("mktme", "name", options_CPU, strlen(options_CPU),
                      KEY_SPEC_THREAD_KEYRING);

    Add a "no-encrypt' type key::

	key = add_key("mktme", "name", "no-encrypt", strlen(options_CPU),
		      KEY_SPEC_THREAD_KEYRING);
