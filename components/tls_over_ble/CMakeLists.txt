idf_component_register(SRCS "ble_tunnel.c" "ble_tls.c" "ble_tls_transport.c"
                       INCLUDE_DIRS "include"
                       REQUIRES bt mbedtls esp_timer tcp_transport
                       PRIV_REQUIRES esp_hw_support)
