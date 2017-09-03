typedef enum {

    /* Operates on standard input/output */
    REPGP_HANDLE_FILE,

    /* Stores filepath to file */
    REPGP_HANDLE_STD,

    /* Operates on memory buffer */
    REPGP_HANDLE_BUFFER

} repgp_handle_type_t;

struct repgp_handle {
    repgp_handle_type_t type;

    union {
        /* Used by REPGP_HANDLE_FILE */
        char *filepath;

        /* Used by REPGP_HANDLE_STD
         * or REPGP_HANDLE_BUFFER */
        struct {
            unsigned char *data;
            size_t         size;
        } std, buffer;
    };
};

struct repgp_io {
    struct repgp_handle *in;
    struct repgp_handle *out;
};
