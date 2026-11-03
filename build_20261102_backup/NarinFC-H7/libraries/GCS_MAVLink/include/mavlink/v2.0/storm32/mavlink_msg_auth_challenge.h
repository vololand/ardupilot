#pragma once
// MESSAGE AUTH_CHALLENGE PACKING

#define MAVLINK_MSG_ID_AUTH_CHALLENGE 60011


typedef struct __mavlink_auth_challenge_t {
 uint32_t timestamp; /*< [ms] Server boot timestamp for this challenge.*/
 uint8_t challenge[8]; /*<  Server-generated random nonce.*/
 uint8_t user_salt[16]; /*<  Per-user salt (random for unknown user).*/
} mavlink_auth_challenge_t;

#define MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN 28
#define MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN 28
#define MAVLINK_MSG_ID_60011_LEN 28
#define MAVLINK_MSG_ID_60011_MIN_LEN 28

#define MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC 176
#define MAVLINK_MSG_ID_60011_CRC 176

#define MAVLINK_MSG_AUTH_CHALLENGE_FIELD_CHALLENGE_LEN 8
#define MAVLINK_MSG_AUTH_CHALLENGE_FIELD_USER_SALT_LEN 16

#if MAVLINK_COMMAND_24BIT
#define MAVLINK_MESSAGE_INFO_AUTH_CHALLENGE { \
    60011, \
    "AUTH_CHALLENGE", \
    3, \
    {  { "challenge", NULL, MAVLINK_TYPE_UINT8_T, 8, 4, offsetof(mavlink_auth_challenge_t, challenge) }, \
         { "user_salt", NULL, MAVLINK_TYPE_UINT8_T, 16, 12, offsetof(mavlink_auth_challenge_t, user_salt) }, \
         { "timestamp", NULL, MAVLINK_TYPE_UINT32_T, 0, 0, offsetof(mavlink_auth_challenge_t, timestamp) }, \
         } \
}
#else
#define MAVLINK_MESSAGE_INFO_AUTH_CHALLENGE { \
    "AUTH_CHALLENGE", \
    3, \
    {  { "challenge", NULL, MAVLINK_TYPE_UINT8_T, 8, 4, offsetof(mavlink_auth_challenge_t, challenge) }, \
         { "user_salt", NULL, MAVLINK_TYPE_UINT8_T, 16, 12, offsetof(mavlink_auth_challenge_t, user_salt) }, \
         { "timestamp", NULL, MAVLINK_TYPE_UINT32_T, 0, 0, offsetof(mavlink_auth_challenge_t, timestamp) }, \
         } \
}
#endif

/**
 * @brief Pack a auth_challenge message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 *
 * @param challenge  Server-generated random nonce.
 * @param user_salt  Per-user salt (random for unknown user).
 * @param timestamp [ms] Server boot timestamp for this challenge.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_challenge_pack(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg,
                               const uint8_t *challenge, const uint8_t *user_salt, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, challenge, 8);
    _mav_put_uint8_t_array(buf, 12, user_salt, 16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#else
    mavlink_auth_challenge_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.challenge, challenge, sizeof(uint8_t)*8);
    mav_array_memcpy(packet.user_salt, user_salt, sizeof(uint8_t)*16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_CHALLENGE;
    return mavlink_finalize_message(msg, system_id, component_id, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
}

/**
 * @brief Pack a auth_challenge message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 *
 * @param challenge  Server-generated random nonce.
 * @param user_salt  Per-user salt (random for unknown user).
 * @param timestamp [ms] Server boot timestamp for this challenge.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_challenge_pack_status(uint8_t system_id, uint8_t component_id, mavlink_status_t *_status, mavlink_message_t* msg,
                               const uint8_t *challenge, const uint8_t *user_salt, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, challenge, 8);
    _mav_put_uint8_t_array(buf, 12, user_salt, 16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#else
    mavlink_auth_challenge_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.challenge, challenge, sizeof(uint8_t)*8);
    mav_array_memcpy(packet.user_salt, user_salt, sizeof(uint8_t)*16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_CHALLENGE;
#if MAVLINK_CRC_EXTRA
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#else
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#endif
}

/**
 * @brief Pack a auth_challenge message on a channel
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param challenge  Server-generated random nonce.
 * @param user_salt  Per-user salt (random for unknown user).
 * @param timestamp [ms] Server boot timestamp for this challenge.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_challenge_pack_chan(uint8_t system_id, uint8_t component_id, uint8_t chan,
                               mavlink_message_t* msg,
                                   const uint8_t *challenge,const uint8_t *user_salt,uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, challenge, 8);
    _mav_put_uint8_t_array(buf, 12, user_salt, 16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#else
    mavlink_auth_challenge_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.challenge, challenge, sizeof(uint8_t)*8);
    mav_array_memcpy(packet.user_salt, user_salt, sizeof(uint8_t)*16);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_CHALLENGE;
    return mavlink_finalize_message_chan(msg, system_id, component_id, chan, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
}

/**
 * @brief Encode a auth_challenge struct
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 * @param auth_challenge C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_challenge_encode(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg, const mavlink_auth_challenge_t* auth_challenge)
{
    return mavlink_msg_auth_challenge_pack(system_id, component_id, msg, auth_challenge->challenge, auth_challenge->user_salt, auth_challenge->timestamp);
}

/**
 * @brief Encode a auth_challenge struct on a channel
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param auth_challenge C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_challenge_encode_chan(uint8_t system_id, uint8_t component_id, uint8_t chan, mavlink_message_t* msg, const mavlink_auth_challenge_t* auth_challenge)
{
    return mavlink_msg_auth_challenge_pack_chan(system_id, component_id, chan, msg, auth_challenge->challenge, auth_challenge->user_salt, auth_challenge->timestamp);
}

/**
 * @brief Encode a auth_challenge struct with provided status structure
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 * @param auth_challenge C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_challenge_encode_status(uint8_t system_id, uint8_t component_id, mavlink_status_t* _status, mavlink_message_t* msg, const mavlink_auth_challenge_t* auth_challenge)
{
    return mavlink_msg_auth_challenge_pack_status(system_id, component_id, _status, msg,  auth_challenge->challenge, auth_challenge->user_salt, auth_challenge->timestamp);
}

/**
 * @brief Send a auth_challenge message
 * @param chan MAVLink channel to send the message
 *
 * @param challenge  Server-generated random nonce.
 * @param user_salt  Per-user salt (random for unknown user).
 * @param timestamp [ms] Server boot timestamp for this challenge.
 */
#ifdef MAVLINK_USE_CONVENIENCE_FUNCTIONS

static inline void mavlink_msg_auth_challenge_send(mavlink_channel_t chan, const uint8_t *challenge, const uint8_t *user_salt, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, challenge, 8);
    _mav_put_uint8_t_array(buf, 12, user_salt, 16);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_CHALLENGE, buf, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#else
    mavlink_auth_challenge_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.challenge, challenge, sizeof(uint8_t)*8);
    mav_array_memcpy(packet.user_salt, user_salt, sizeof(uint8_t)*16);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_CHALLENGE, (const char *)&packet, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#endif
}

/**
 * @brief Send a auth_challenge message
 * @param chan MAVLink channel to send the message
 * @param struct The MAVLink struct to serialize
 */
static inline void mavlink_msg_auth_challenge_send_struct(mavlink_channel_t chan, const mavlink_auth_challenge_t* auth_challenge)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    mavlink_msg_auth_challenge_send(chan, auth_challenge->challenge, auth_challenge->user_salt, auth_challenge->timestamp);
#else
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_CHALLENGE, (const char *)auth_challenge, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#endif
}

#if MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN <= MAVLINK_MAX_PAYLOAD_LEN
/*
  This variant of _send() can be used to save stack space by re-using
  memory from the receive buffer.  The caller provides a
  mavlink_message_t which is the size of a full mavlink message. This
  is usually the receive buffer for the channel, and allows a reply to an
  incoming message with minimum stack space usage.
 */
static inline void mavlink_msg_auth_challenge_send_buf(mavlink_message_t *msgbuf, mavlink_channel_t chan,  const uint8_t *challenge, const uint8_t *user_salt, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char *buf = (char *)msgbuf;
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, challenge, 8);
    _mav_put_uint8_t_array(buf, 12, user_salt, 16);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_CHALLENGE, buf, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#else
    mavlink_auth_challenge_t *packet = (mavlink_auth_challenge_t *)msgbuf;
    packet->timestamp = timestamp;
    mav_array_memcpy(packet->challenge, challenge, sizeof(uint8_t)*8);
    mav_array_memcpy(packet->user_salt, user_salt, sizeof(uint8_t)*16);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_CHALLENGE, (const char *)packet, MAVLINK_MSG_ID_AUTH_CHALLENGE_MIN_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN, MAVLINK_MSG_ID_AUTH_CHALLENGE_CRC);
#endif
}
#endif

#endif

// MESSAGE AUTH_CHALLENGE UNPACKING


/**
 * @brief Get field challenge from auth_challenge message
 *
 * @return  Server-generated random nonce.
 */
static inline uint16_t mavlink_msg_auth_challenge_get_challenge(const mavlink_message_t* msg, uint8_t *challenge)
{
    return _MAV_RETURN_uint8_t_array(msg, challenge, 8,  4);
}

/**
 * @brief Get field user_salt from auth_challenge message
 *
 * @return  Per-user salt (random for unknown user).
 */
static inline uint16_t mavlink_msg_auth_challenge_get_user_salt(const mavlink_message_t* msg, uint8_t *user_salt)
{
    return _MAV_RETURN_uint8_t_array(msg, user_salt, 16,  12);
}

/**
 * @brief Get field timestamp from auth_challenge message
 *
 * @return [ms] Server boot timestamp for this challenge.
 */
static inline uint32_t mavlink_msg_auth_challenge_get_timestamp(const mavlink_message_t* msg)
{
    return _MAV_RETURN_uint32_t(msg,  0);
}

/**
 * @brief Decode a auth_challenge message into a struct
 *
 * @param msg The message to decode
 * @param auth_challenge C-struct to decode the message contents into
 */
static inline void mavlink_msg_auth_challenge_decode(const mavlink_message_t* msg, mavlink_auth_challenge_t* auth_challenge)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    auth_challenge->timestamp = mavlink_msg_auth_challenge_get_timestamp(msg);
    mavlink_msg_auth_challenge_get_challenge(msg, auth_challenge->challenge);
    mavlink_msg_auth_challenge_get_user_salt(msg, auth_challenge->user_salt);
#else
        uint8_t len = msg->len < MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN? msg->len : MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN;
        memset(auth_challenge, 0, MAVLINK_MSG_ID_AUTH_CHALLENGE_LEN);
    memcpy(auth_challenge, _MAV_PAYLOAD(msg), len);
#endif
}
