MKTME Configuration
===================

CONFIG_X86_INTEL_MKTME
        MKTME is enabled by selecting CONFIG_X86_INTEL_MKTME on Intel
        platforms supporting the MKTME feature.

mktme_storekeys
        mktme_storekeys is a kernel cmdline parameter.

        This parameter allows the kernel to store the user specified
        MKTME key payload. Storing this payload means that the MKTME
        Key Service can always allow the addition of new physical
        packages. If the mktme_storekeys parameter is not present,
        users key data will not be stored, and new physical packages
        may only be added to the system if no user type MKTME keys
        are programmed.
