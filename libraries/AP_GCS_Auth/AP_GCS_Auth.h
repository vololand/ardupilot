#pragma once

#include <GCS_MAVLink/GCS_config.h>

#if HAL_GCS_ENABLED

#include <GCS_MAVLink/GCS_MAVLink.h>

class GCS_MAVLINK;

class AP_GCS_Auth {
public:
    static AP_GCS_Auth &get_singleton();

    bool handle_message(GCS_MAVLINK &link, const mavlink_message_t &msg);
    bool is_message_allowed(mavlink_channel_t chan, uint32_t msgid) const;
    bool allow_unsigned_message(const mavlink_status_t *status, uint32_t msgid) const;
    bool is_channel_authenticated(mavlink_channel_t chan) const;
    bool is_usb_bypass_channel(mavlink_channel_t chan) const;
    void clear_channel_auth(mavlink_channel_t chan);

private:
    static constexpr uint8_t MAX_USERS = 10;
    static constexpr uint8_t USER_ID_LEN = 32;
    static constexpr uint8_t PW_HASH_LEN = 32;
    static constexpr uint8_t USER_SALT_LEN = 16;
    static constexpr uint8_t CHALLENGE_LEN = 8;

    struct AuthRecord {
        char user_id[USER_ID_LEN];
        uint8_t pw_hash[PW_HASH_LEN];
        uint8_t user_salt[USER_SALT_LEN];
    };

    struct AuthSession {
        bool pending = false;
        bool authenticated = false;
        uint8_t challenge[CHALLENGE_LEN] {};
        uint8_t expected_pw_hash[PW_HASH_LEN] {};
        char user_id[USER_ID_LEN] {};
        uint32_t timestamp_ms = 0;
        uint8_t retries_left = 0;
    };

    AuthSession _sessions[MAVLINK_COMM_NUM_BUFFERS];

    bool handle_auth_request(GCS_MAVLINK &link, const mavlink_auth_request_t &pkt);
    bool handle_auth_response(GCS_MAVLINK &link, const mavlink_auth_response_t &pkt);

    bool find_user_record(GCS_MAVLINK &link, const char user_id[USER_ID_LEN], AuthRecord &record) const;
    static void fill_random_bytes(uint8_t *buf, uint8_t len);
    static void normalize_user_id(const char in[USER_ID_LEN], char out[USER_ID_LEN]);
    static bool is_login_msg(uint32_t msgid);
    static bool is_pre_auth_allowed_msg(uint32_t msgid);
    static void sha256_32(const uint8_t *buf1, uint32_t len1,
                          const uint8_t *buf2, uint32_t len2,
                          uint8_t out[32]);
    static void sha256_32_3(const uint8_t *buf1, uint32_t len1,
                            const uint8_t *buf2, uint32_t len2,
                            const uint8_t *buf3, uint32_t len3,
                            uint8_t out[32]);
    static bool const_time_eq(const uint8_t *a, const uint8_t *b, uint8_t len);
};

#endif // HAL_GCS_ENABLED
