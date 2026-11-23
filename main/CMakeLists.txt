set(embed_txt "")
if(CONFIG_APP_OTA_DEMO AND CONFIG_APP_OTA_CA_EMBEDDED)
    # Created by tools/ota_server/ota_server.py init (not in the repository)
    if(NOT EXISTS "${CMAKE_CURRENT_LIST_DIR}/ota_ca.pem")
        message(FATAL_ERROR
            "main/ota_ca.pem not found. Create your own test CA first:\n"
            "  python tools/ota_server/ota_server.py init\n"
            "  python tools/ota_server/ota_server.py device\n"
            "or turn off the OTA demo (menuconfig: CONFIG_APP_OTA_DEMO).")
    endif()
    list(APPEND embed_txt "ota_ca.pem")
endif()

idf_component_register(SRCS "main.cpp" "hid_kbd.c"
                       INCLUDE_DIRS "."
                       REQUIRES bt nvs_flash esp_driver_gpio esp_timer esp_event mbedtls
                                esp_http_client esp_https_ota app_update esp_app_format
                                tls_over_ble
                       EMBED_TXTFILES ${embed_txt})

# Device identity for the "fctry" partition, created by tools/ota_server/ota_server.py device.
# idf.py flash writes it; it is not part of the app image, so OTA images carry no key.
get_filename_component(id_dir "${CMAKE_CURRENT_LIST_DIR}/../tools/certs" ABSOLUTE)
set(id_cert "${id_dir}/device.crt.der")
set(id_key "${id_dir}/device.key.der")
if(EXISTS "${id_cert}" AND EXISTS "${id_key}")
    # nvs_partition_gen.py input; written here with absolute paths for this checkout
    set(fctry_csv "${CMAKE_BINARY_DIR}/fctry.csv")
    file(WRITE "${fctry_csv}"
         "key,type,encoding,value\n"
         "fctry,namespace,,\n"
         "dev_cert,file,binary,${id_cert}\n"
         "dev_key,file,binary,${id_key}\n")
    nvs_create_partition_image(fctry "${fctry_csv}" FLASH_IN_PROJECT
                               DEPENDS "${id_cert}" "${id_key}")
else()
    message(STATUS "No device identity in ${id_dir}; "
                   "run 'python tools/ota_server/ota_server.py device' to create one")
endif()
