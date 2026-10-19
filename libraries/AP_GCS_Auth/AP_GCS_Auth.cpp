#include "AP_GCS_Auth.h"

#if HAL_GCS_ENABLED

#include <GCS_MAVLink/GCS.h>
#include <AP_HAL/HAL.h>
#include <AP_Math/AP_Math.h>
#include <AP_Filesystem/AP_Filesystem.h>

extern const AP_HAL::HAL &hal;

AP_GCS_Auth *AP_GCS_Auth::_singleton;

AP_GCS_Auth::AP_GCS_Auth()
{
    if (_singleton == nullptr) {
        _singleton = this;
    }
}

struct mavlink_sha256_ctx {
    uint32_t sz[2];
    uint32_t counter[8];
    union {
        unsigned char save_bytes[64];
        uint32_t save_u32[16];
    } u;
};

extern void mavlink_sha256_init(mavlink_sha256_ctx *m);
extern void mavlink_sha256_update(mavlink_sha256_ctx *m, const void *v, uint32_t len);

namespace {
constexpr uint8_t USER_ID_LEN = 32;
constexpr uint32_t AUTH_TIMEOUT_MS = 10000;
constexpr uint8_t AUTH_MAX_RETRIES = 3;
constexpr const char *AUTH_DB_PRIMARY = "/APM/auth.dat";
constexpr const char *USB_NO_AUTH_PATH = "/APM/USB_NO_AUTH";
constexpr const char *AUTH_OFF_PATH = "/APM/AUTH_OFF";
constexpr const char *NO_SIGNATURE_PATH = "/APM/MAVLINK_V2_NO_SIGNATURE";
#if CONFIG_HAL_BOARD == HAL_BOARD_SITL
constexpr const char *AUTH_DB_FALLBACK = "auth.dat";
#else
constexpr const char *AUTH_DB_FALLBACK = "/auth.dat";
#endif

struct UsbNoAuthCache {
    bool valid;
    bool present;
};

UsbNoAuthCache usb_no_auth_cache;
UsbNoAuthCache auth_off_cache;
UsbNoAuthCache no_signature_cache;

// force=true on AUTH_REQUEST. Otherwise reuse the last result.
bool marker_file_present(UsbNoAuthCache &cache, const char *path, bool force,
                         const char *present_msg, const char *absent_msg)
{
    if (!force && cache.valid) {
        return cache.present;
    }

    const int fd = AP::FS().open(path, O_RDONLY, true);
    const bool present = fd >= 0;
    if (present) {
        AP::FS().close(fd);
    }
    const bool announce = (cache.valid && cache.present != present) ||
                          (!cache.valid && present);
    cache.valid = true;
    cache.present = present;
    if (announce) {
        GCS_SEND_TEXT(present ? MAV_SEVERITY_INFO : MAV_SEVERITY_NOTICE, "%s",
                      present ? present_msg : absent_msg);
    }
    return present;
}

bool usb_no_auth_file_present(bool force)
{
    return marker_file_present(usb_no_auth_cache, USB_NO_AUTH_PATH, force,
                               "AUTH: /APM/USB_NO_AUTH present, USB auth bypass",
                               "AUTH: /APM/USB_NO_AUTH absent, USB auth required");
}

bool auth_off_file_present(bool force)
{
    return marker_file_present(auth_off_cache, AUTH_OFF_PATH, force,
                               "AUTH: /APM/AUTH_OFF present, login disabled",
                               "AUTH: /APM/AUTH_OFF absent, login required");
}

bool no_signature_file_present(bool force)
{
    return marker_file_present(no_signature_cache, NO_SIGNATURE_PATH, force,
                               "AUTH: /APM/MAVLINK_V2_NO_SIGNATURE present, signature disabled",
                               "AUTH: /APM/MAVLINK_V2_NO_SIGNATURE absent, signature enabled");
}

bool is_usb_uart_channel(mavlink_channel_t chan)
{
    if (chan >= MAVLINK_COMM_NUM_BUFFERS) {
        return false;
    }
    const uint8_t ofs = uint8_t(chan - MAVLINK_COMM_0);
    const GCS_MAVLINK *link = gcs().chan(ofs);
    if (link == nullptr) {
        return false;
    }
    AP_HAL::UARTDriver *uart = const_cast<GCS_MAVLINK *>(link)->get_uart();
    return uart != nullptr && uart->get_usb_baud() != 0;
}

void sha256_final_32(mavlink_sha256_ctx *ctx_in, uint8_t result[32])
{
    auto *ctx = reinterpret_cast<mavlink_sha256_ctx *>(ctx_in);
    unsigned char zeros[72] {};
    const unsigned offset = (ctx->sz[0] / 8U) % 64U;
    const unsigned dstart = (120U - offset - 1U) % 64U + 1U;

    zeros[0] = 0x80;
    zeros[dstart+7] = (ctx->sz[0] >> 0) & 0xff;
    zeros[dstart+6] = (ctx->sz[0] >> 8) & 0xff;
    zeros[dstart+5] = (ctx->sz[0] >> 16) & 0xff;
    zeros[dstart+4] = (ctx->sz[0] >> 24) & 0xff;
    zeros[dstart+3] = (ctx->sz[1] >> 0) & 0xff;
    zeros[dstart+2] = (ctx->sz[1] >> 8) & 0xff;
    zeros[dstart+1] = (ctx->sz[1] >> 16) & 0xff;
    zeros[dstart+0] = (ctx->sz[1] >> 24) & 0xff;

    mavlink_sha256_update(ctx_in, zeros, dstart + 8U);

    for (uint8_t i = 0; i < 8; i++) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(&ctx->counter[i]);
        result[i*4 + 0] = p[3];
        result[i*4 + 1] = p[2];
        result[i*4 + 2] = p[1];
        result[i*4 + 3] = p[0];
    }
}

// GCS: pendingLoginId.getBytes(UTF-8) — zero-pad 없이 실제 문자열 길이만 사용
uint8_t user_id_byte_len(const char user_id[USER_ID_LEN])
{
    uint8_t len = 0;
    while (len < USER_ID_LEN - 1 && user_id[len] != '\0') {
        len++;
    }
    return len;
}
} // namespace

AP_GCS_Auth &AP_GCS_Auth::get_singleton()
{
    if (_singleton == nullptr) {
        static AP_GCS_Auth fallback;
        (void)fallback;
    }
    return *_singleton;
}

void AP_GCS_Auth::fill_random_bytes(uint8_t *buf, uint8_t len)
{
    for (uint8_t i = 0; i < len; i += 2) {
        const uint16_t rnd = get_random16();
        buf[i] = rnd & 0xFFU;
        if (i + 1 < len) {
            buf[i+1] = rnd >> 8;
        }
    }
}

void AP_GCS_Auth::normalize_user_id(const char in[USER_ID_LEN], char out[USER_ID_LEN])
{
    memset(out, 0, USER_ID_LEN);
    for (uint8_t i = 0; i < USER_ID_LEN-1; i++) {
        if (in[i] == 0) {
            break;
        }
        out[i] = in[i];
    }
    out[USER_ID_LEN-1] = 0;
}

bool AP_GCS_Auth::const_time_eq(const uint8_t *a, const uint8_t *b, uint8_t len)
{
    uint8_t diff = 0;
    for (uint8_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }
    return diff == 0;
}

void AP_GCS_Auth::sha256_32(const uint8_t *buf1, uint32_t len1,
                            const uint8_t *buf2, uint32_t len2,
                            uint8_t out[32])
{
    mavlink_sha256_ctx ctx {};
    mavlink_sha256_init(&ctx);
    mavlink_sha256_update(&ctx, buf1, len1);
    mavlink_sha256_update(&ctx, buf2, len2);
    sha256_final_32(&ctx, out);
}

void AP_GCS_Auth::sha256_32_3(const uint8_t *buf1, uint32_t len1,
                              const uint8_t *buf2, uint32_t len2,
                              const uint8_t *buf3, uint32_t len3,
                              uint8_t out[32])
{
    mavlink_sha256_ctx ctx {};
    mavlink_sha256_init(&ctx);
    mavlink_sha256_update(&ctx, buf1, len1);
    mavlink_sha256_update(&ctx, buf2, len2);
    mavlink_sha256_update(&ctx, buf3, len3);
    sha256_final_32(&ctx, out);
}

void AP_GCS_Auth::send_exit_code(GCS_MAVLINK &link, AuthExitCode code)
{
    const char *name;
    switch (code) {
    case AUTH_EXIT_SUCCESS:      name = "AUTH_EXIT_SUCCESS"; break;
    case AUTH_EXIT_INVALID_ARGS: name = "AUTH_EXIT_INVALID_ARGS"; break;
    case AUTH_EXIT_FILE_ERROR:   name = "AUTH_EXIT_FILE_ERROR"; break;
    case AUTH_EXIT_INVALID_DB:   name = "AUTH_EXIT_INVALID_DB"; break;
    case AUTH_EXIT_NOT_FOUND:    name = "AUTH_EXIT_NOT_FOUND"; break;
    case AUTH_EXIT_EXISTS:       name = "AUTH_EXIT_EXISTS"; break;
    case AUTH_EXIT_PW_MISMATCH:  name = "AUTH_EXIT_PW_MISMATCH"; break;
    case AUTH_EXIT_CRYPTO_ERROR: name = "AUTH_EXIT_CRYPTO_ERROR"; break;
    default:                     name = "AUTH_EXIT_UNKNOWN"; break;
    }

    char text[MAVLINK_MSG_STATUSTEXT_FIELD_TEXT_LEN] {};
    hal.util->snprintf(text, sizeof(text), "%s=%u", name, unsigned(code));
    const MAV_SEVERITY sev = (code == AUTH_EXIT_SUCCESS) ? MAV_SEVERITY_INFO : MAV_SEVERITY_WARNING;
    // Direct send: the pre-auth stream suppresses queued STATUSTEXT.
    mavlink_msg_statustext_send(link.get_chan(), sev, text, 0, 0);
}

AP_GCS_Auth::DbLookupStatus AP_GCS_Auth::find_user_record(GCS_MAVLINK &link, const char user_id[USER_ID_LEN], AuthRecord &record) const
{
    const char *paths[] = { AUTH_DB_PRIMARY, AUTH_DB_FALLBACK };
    bool any_open_ok = false;
    bool saw_invalid_db = false;

    for (const char *path : paths) {
        int fd = AP::FS().open(path, O_RDONLY, true);
        if (fd < 0) {
            link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: auth db open failed path=%s", path);
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: auth db open failed path=%s", path);
            continue;
        }
        any_open_ok = true;
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: auth db open ok path=%s", path);
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: auth db open ok path=%s", path);

        for (uint8_t i = 0; i < MAX_USERS; i++) {
            AuthRecord rec {};
            const int32_t n = AP::FS().read(fd, &rec, sizeof(rec));
            if (n == 0) {
                break;
            }
            if (n != int32_t(sizeof(rec))) {
                saw_invalid_db = true;
                break;
            }
            if (rec.user_id[0] == 0) {
                continue;
            }
            char normalized[USER_ID_LEN] {};
            normalize_user_id(rec.user_id, normalized);
            if (memcmp(normalized, user_id, USER_ID_LEN) == 0) {
                AP::FS().close(fd);
                record = rec;
                return DbLookupStatus::OK;
            }
        }
        AP::FS().close(fd);
    }

    if (!any_open_ok) {
        return DbLookupStatus::FILE_ERROR;
    }
    if (saw_invalid_db) {
        return DbLookupStatus::INVALID_DB;
    }
    return DbLookupStatus::NOT_FOUND;
}

bool AP_GCS_Auth::is_login_msg(uint32_t msgid)
{
    return msgid == MAVLINK_MSG_ID_AUTH_REQUEST ||
           msgid == MAVLINK_MSG_ID_AUTH_RESPONSE;
}

bool AP_GCS_Auth::is_pre_auth_allowed_msg(uint32_t msgid)
{
    return is_login_msg(msgid) ||
           msgid == MAVLINK_MSG_ID_HEARTBEAT ||
           msgid == MAVLINK_MSG_ID_TIMESYNC;
}

bool AP_GCS_Auth::is_auth_disabled() const
{
    return auth_off_file_present(false);
}

bool AP_GCS_Auth::is_signature_disabled() const
{
    return no_signature_file_present(false);
}

bool AP_GCS_Auth::is_channel_authenticated(mavlink_channel_t chan) const
{
    if (chan >= MAVLINK_COMM_NUM_BUFFERS) {
        return false;
    }
    if (is_auth_disabled() || is_usb_no_auth_channel(chan)) {
        return true;
    }
    return _sessions[chan].authenticated;
}

void AP_GCS_Auth::clear_channel_auth(mavlink_channel_t chan)
{
    if (chan >= MAVLINK_COMM_NUM_BUFFERS) {
        return;
    }
    _sessions[chan].authenticated = false;
    _sessions[chan].pending = false;
    _sessions[chan].user_known = false;
}

bool AP_GCS_Auth::is_message_allowed(mavlink_channel_t chan, uint32_t msgid) const
{
    if (chan >= MAVLINK_COMM_NUM_BUFFERS) {
        return false;
    }
    if (is_auth_disabled() || is_usb_no_auth_channel(chan)) {
        return true;
    }
    if (_sessions[chan].authenticated) {
        return true;
    }
    return is_pre_auth_allowed_msg(msgid);
}

bool AP_GCS_Auth::allow_unsigned_message(const mavlink_status_t *status, uint32_t msgid) const
{
    if (is_auth_disabled() || is_signature_disabled() || is_pre_auth_allowed_msg(msgid)) {
        return true;
    }
    for (uint8_t i = 0; i < MAVLINK_COMM_NUM_BUFFERS; i++) {
        if (status == mavlink_get_channel_status(mavlink_channel_t(MAVLINK_COMM_0 + i))) {
            if (is_usb_no_auth_channel(mavlink_channel_t(MAVLINK_COMM_0 + i))) {
                return true;
            }
            // Logged-in channels require a MAVLink2 signature unless the no-signature file is present.
            return false;
        }
    }
    return false;
}

bool AP_GCS_Auth::is_usb_no_auth_channel(mavlink_channel_t chan) const
{
    return is_usb_uart_channel(chan) && usb_no_auth_file_present(false);
}

bool AP_GCS_Auth::handle_auth_request(GCS_MAVLINK &link, const mavlink_auth_request_t &pkt)
{
    if (auth_off_file_present(true)) {
        auto &session = _sessions[link.get_chan()];
        session.pending = false;
        session.authenticated = true;
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: AUTH_OFF bypass (ch=%u)", unsigned(link.get_chan()));
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: AUTH_OFF bypass (ch=%u)", unsigned(link.get_chan()));

        mavlink_auth_result_t result {};
        result.result = MAV_AUTH_RESULT_ACCEPTED;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        send_exit_code(link, AUTH_EXIT_SUCCESS);
        return true;
    }

    if (usb_no_auth_file_present(true) && is_usb_uart_channel(link.get_chan())) {
        auto &session = _sessions[link.get_chan()];
        session.pending = false;
        session.authenticated = true;
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: USB_NO_AUTH bypass (ch=%u)", unsigned(link.get_chan()));
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: USB_NO_AUTH bypass (ch=%u)", unsigned(link.get_chan()));

        mavlink_auth_result_t result {};
        result.result = MAV_AUTH_RESULT_ACCEPTED;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        send_exit_code(link, AUTH_EXIT_SUCCESS);
        return true;
    }

    if (pkt.target_system != 0 && pkt.target_system != mavlink_system.sysid) {
        link.send_text(MAV_SEVERITY_WARNING,
                       "AUTH_link: target mismatch req=%u self=%u",
                       unsigned(pkt.target_system),
                       unsigned(mavlink_system.sysid));
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING,
                      "AUTH_GCS: target mismatch req=%u self=%u",
                      unsigned(pkt.target_system),
                      unsigned(mavlink_system.sysid));
        send_exit_code(link, AUTH_EXIT_INVALID_ARGS);
        return true;
    }

    auto &session = _sessions[link.get_chan()];
    if (pkt.request_type == MAV_AUTH_TYPE_LOGOUT) {
        clear_channel_auth(link.get_chan());
        if (no_signature_file_present(true)) {
            link.clear_signing_key();
        } else {
            uint8_t random_key[32] {};
            fill_random_bytes(random_key, sizeof(random_key));
            link.apply_signing_key(random_key, AP_HAL::micros64()/10ULL);
        }
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: logout accepted (ch=%u)", unsigned(link.get_chan()));
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: logout accepted (ch=%u)", unsigned(link.get_chan()));

        mavlink_auth_result_t result {};
        result.result = MAV_AUTH_RESULT_ACCEPTED;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        send_exit_code(link, AUTH_EXIT_SUCCESS);
        return true;
    }

    if (pkt.request_type != MAV_AUTH_TYPE_LOGIN) {
        link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: unsupported request type=%u", unsigned(pkt.request_type));
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: unsupported request type=%u", unsigned(pkt.request_type));
        mavlink_auth_result_t result {};
        result.result = MAV_AUTH_RESULT_FAILED;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        send_exit_code(link, AUTH_EXIT_INVALID_ARGS);
        return true;
    }

    char user_id[USER_ID_LEN] {};
    normalize_user_id(pkt.user_id, user_id);
    if (user_id[0] == 0) {
        mavlink_auth_result_t result {};
        result.result = MAV_AUTH_RESULT_FAILED;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        send_exit_code(link, AUTH_EXIT_INVALID_ARGS);
        return true;
    }

    AuthRecord rec {};
    const DbLookupStatus lookup = find_user_record(link, user_id, rec);
    const bool user_found = (lookup == DbLookupStatus::OK);
    if (!user_found) {
        switch (lookup) {
        case DbLookupStatus::FILE_ERROR:
            send_exit_code(link, AUTH_EXIT_FILE_ERROR);
            break;
        case DbLookupStatus::INVALID_DB:
            send_exit_code(link, AUTH_EXIT_INVALID_DB);
            break;
        case DbLookupStatus::NOT_FOUND:
        default:
            send_exit_code(link, AUTH_EXIT_NOT_FOUND);
            break;
        }
    }
    if (user_found) {
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: login request user='%s'", user_id);
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: login request user='%s'", user_id);
    } else {
        // avoid user-enumeration details to remote peer; keep this only as local debug text.
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: login request unknown user");
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: login request unknown user");
    }

    session.pending = true;
    session.authenticated = false;
    session.user_known = user_found;
    session.timestamp_ms = AP_HAL::millis();
    session.retries_left = AUTH_MAX_RETRIES;
    memcpy(session.user_id, user_id, USER_ID_LEN);
    fill_random_bytes(session.challenge, CHALLENGE_LEN);
    if (user_found) {
        memcpy(session.expected_pw_hash, rec.pw_hash, PW_HASH_LEN);
    } else {
        fill_random_bytes(session.expected_pw_hash, PW_HASH_LEN);
    }

    mavlink_auth_challenge_t challenge {};
    memcpy(challenge.challenge, session.challenge, CHALLENGE_LEN);
    if (user_found) {
        memcpy(challenge.user_salt, rec.user_salt, USER_SALT_LEN);
    } else {
        fill_random_bytes(challenge.user_salt, USER_SALT_LEN);
    }
    challenge.timestamp = session.timestamp_ms;
    mavlink_msg_auth_challenge_send_struct(link.get_chan(), &challenge);
    link.send_text(MAV_SEVERITY_INFO, "AUTH_link: challenge sent (ch=%u ts=%lu)",
                   unsigned(link.get_chan()),
                   static_cast<unsigned long>(challenge.timestamp));
    GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: challenge sent (ch=%u ts=%lu)",
                   unsigned(link.get_chan()),
                   static_cast<unsigned long>(challenge.timestamp));
    return true;
}

bool AP_GCS_Auth::handle_auth_response(GCS_MAVLINK &link, const mavlink_auth_response_t &pkt)
{
    auto &session = _sessions[link.get_chan()];
    mavlink_auth_result_t result {};
    result.result = MAV_AUTH_RESULT_FAILED;

    if (!session.pending ||
        pkt.timestamp != session.timestamp_ms ||
        AP_HAL::millis() - session.timestamp_ms > AUTH_TIMEOUT_MS) {
        if (!session.pending) {
            link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: response without pending session");
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: response without pending session");
        } else if (pkt.timestamp != session.timestamp_ms) {
            link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: timestamp mismatch");
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: timestamp mismatch");
        } else {
            link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: response timeout");
            GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: response timeout");
        }
        send_exit_code(link, AUTH_EXIT_INVALID_ARGS);
        session.pending = false;
        session.authenticated = false;
        session.user_known = false;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        return true;
    }

    uint8_t expected[32] {};
    sha256_32(session.expected_pw_hash, PW_HASH_LEN,
              session.challenge, CHALLENGE_LEN,
              expected);

    if (!const_time_eq(expected, pkt.response, sizeof(expected))) {
        if (session.retries_left > 0) {
            session.retries_left--;
        }
        if (session.retries_left == 0) {
            session.pending = false;
        }
        link.send_text(MAV_SEVERITY_WARNING, "AUTH_link: bad response retries_left=%u",
                       unsigned(session.retries_left));
        GCS_SEND_TEXT(MAV_SEVERITY_WARNING, "AUTH_GCS: bad response retries_left=%u",
                       unsigned(session.retries_left));
        send_exit_code(link, session.user_known ? AUTH_EXIT_PW_MISMATCH : AUTH_EXIT_NOT_FOUND);
        session.authenticated = false;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        return true;
    }

    if (!session.user_known) {
        send_exit_code(link, AUTH_EXIT_NOT_FOUND);
        session.pending = false;
        session.authenticated = false;
        mavlink_msg_auth_result_send_struct(link.get_chan(), &result);
        return true;
    }

    session.pending = false;
    session.authenticated = true;
    result.result = MAV_AUTH_RESULT_ACCEPTED;
    mavlink_msg_auth_result_send_struct(link.get_chan(), &result);

    if (no_signature_file_present(true)) {
        link.clear_signing_key();
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: accepted user='%s' unsigned session", session.user_id);
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: accepted user='%s' unsigned session", session.user_id);
    } else {
        // K = SHA256(user_id_utf8 + H + challenge)
        const uint8_t uid_len = user_id_byte_len(session.user_id);
        uint8_t signing_key[32] {};
        sha256_32_3(reinterpret_cast<const uint8_t *>(session.user_id), uid_len,
                    session.expected_pw_hash, PW_HASH_LEN,
                    session.challenge, CHALLENGE_LEN,
                    signing_key);
        link.apply_signing_key(signing_key, AP_HAL::micros64()/10ULL);
        link.send_text(MAV_SEVERITY_INFO, "AUTH_link: accepted user='%s' signing_key applied", session.user_id);
        GCS_SEND_TEXT(MAV_SEVERITY_INFO, "AUTH_GCS: accepted user='%s' signing_key applied", session.user_id);
    }
    send_exit_code(link, AUTH_EXIT_SUCCESS);

    return true;
}

bool AP_GCS_Auth::handle_message(GCS_MAVLINK &link, const mavlink_message_t &msg)
{
    switch (msg.msgid) {
    case MAVLINK_MSG_ID_AUTH_REQUEST: {
        mavlink_auth_request_t pkt {};
        mavlink_msg_auth_request_decode(&msg, &pkt);
        return handle_auth_request(link, pkt);
    }
    case MAVLINK_MSG_ID_AUTH_RESPONSE: {
        mavlink_auth_response_t pkt {};
        mavlink_msg_auth_response_decode(&msg, &pkt);
        return handle_auth_response(link, pkt);
    }
    default:
        break;
    }
    return false;
}

#endif // HAL_GCS_ENABLED
