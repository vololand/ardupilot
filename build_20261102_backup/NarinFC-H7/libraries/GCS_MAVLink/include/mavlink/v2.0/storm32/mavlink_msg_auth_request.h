#pragma once
// MESSAGE AUTH_REQUEST PACKING

#define MAVLINK_MSG_ID_AUTH_REQUEST 60010


typedef struct __mavlink_auth_request_t {
 uint8_t target_system; /*<  Target system ID.*/
 uint8_t request_type; /*<  Authentication request type.*/
 char user_id[32]; /*<  Null-terminated user identifier.*/
} mavlink_auth_request_t;

#define MAVLINK_MSG_ID_AUTH_REQUEST_LEN 34
#define MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN 34
#define MAVLINK_MSG_ID_60010_LEN 34
#define MAVLINK_MSG_ID_60010_MIN_LEN 34

#define MAVLINK_MSG_ID_AUTH_REQUEST_CRC 94
#define MAVLINK_MSG_ID_60010_CRC 94

#define MAVLINK_MSG_AUTH_REQUEST_FIELD_USER_ID_LEN 32

#if MAVLINK_COMMAND_24BIT
#define MAVLINK_MESSAGE_INFO_AUTH_REQUEST { \
    60010, \
    "AUTH_REQUEST", \
    3, \
    {  { "target_system", NULL, MAVLINK_TYPE_UINT8_T, 0, 0, offsetof(mavlink_auth_request_t, target_system) }, \
         { "request_type", NULL, MAVLINK_TYPE_UINT8_T, 0, 1, offsetof(mavlink_auth_request_t, request_type) }, \
         { "user_id", NULL, MAVLINK_TYPE_CHAR, 32, 2, offsetof(mavlink_auth_request_t, user_id) }, \
         } \
}
#else
#define MAVLINK_MESSAGE_INFO_AUTH_REQUEST { \
    "AUTH_REQUEST", \
    3, \
    {  { "target_system", NULL, MAVLINK_TYPE_UINT8_T, 0, 0, offsetof(mavlink_auth_request_t, target_system) }, \
         { "request_type", NULL, MAVLINK_TYPE_UINT8_T, 0, 1, offsetof(mavlink_auth_request_t, request_type) }, \
         { "user_id", NULL, MAVLINK_TYPE_CHAR, 32, 2, offsetof(mavlink_auth_request_t, user_id) }, \
         } \
}
#endif

/**
 * @brief Pack a auth_request message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 *
 * @param target_system  Target system ID.
 * @param request_type  Authentication request type.
 * @param user_id  Null-terminated user identifier.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_request_pack(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg,
                               uint8_t target_system, uint8_t request_type, const char *user_id)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_REQUEST_LEN];
    _mav_put_uint8_t(buf, 0, target_system);
    _mav_put_uint8_t(buf, 1, request_type);
    _mav_put_char_array(buf, 2, user_id, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#else
    mavlink_auth_request_t packet;
    packet.target_system = target_system;
    packet.request_type = request_type;
    mav_array_memcpy(packet.user_id, user_id, sizeof(char)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_REQUEST;
    return mavlink_finalize_message(msg, system_id, component_id, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
}

/**
 * @brief Pack a auth_request message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 *
 * @param target_system  Target system ID.
 * @param request_type  Authentication request type.
 * @param user_id  Null-terminated user identifier.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_request_pack_status(uint8_t system_id, uint8_t component_id, mavlink_status_t *_status, mavlink_message_t* msg,
                               uint8_t target_system, uint8_t request_type, const char *user_id)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_REQUEST_LEN];
    _mav_put_uint8_t(buf, 0, target_system);
    _mav_put_uint8_t(buf, 1, request_type);
    _mav_put_char_array(buf, 2, user_id, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#else
    mavlink_auth_request_t packet;
    packet.target_system = target_system;
    packet.request_type = request_type;
    mav_array_memcpy(packet.user_id, user_id, sizeof(char)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_REQUEST;
#if MAVLINK_CRC_EXTRA
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#else
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#endif
}

/**
 * @brief Pack a auth_request message on a channel
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param target_system  Target system ID.
 * @param request_type  Authentication request type.
 * @param user_id  Null-terminated user identifier.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_request_pack_chan(uint8_t system_id, uint8_t component_id, uint8_t chan,
                               mavlink_message_t* msg,
                                   uint8_t target_system,uint8_t request_type,const char *user_id)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_REQUEST_LEN];
    _mav_put_uint8_t(buf, 0, target_system);
    _mav_put_uint8_t(buf, 1, request_type);
    _mav_put_char_array(buf, 2, user_id, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#else
    mavlink_auth_request_t packet;
    packet.target_system = target_system;
    packet.request_type = request_type;
    mav_array_memcpy(packet.user_id, user_id, sizeof(char)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_REQUEST;
    return mavlink_finalize_message_chan(msg, system_id, component_id, chan, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
}

/**
 * @brief Encode a auth_request struct
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 * @param auth_request C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_request_encode(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg, const mavlink_auth_request_t* auth_request)
{
    return mavlink_msg_auth_request_pack(system_id, component_id, msg, auth_request->target_system, auth_request->request_type, auth_request->user_id);
}

/**
 * @brief Encode a auth_request struct on a channel
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param auth_request C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_request_encode_chan(uint8_t system_id, uint8_t component_id, uint8_t chan, mavlink_message_t* msg, const mavlink_auth_request_t* auth_request)
{
    return mavlink_msg_auth_request_pack_chan(system_id, component_id, chan, msg, auth_request->target_system, auth_request->request_type, auth_request->user_id);
}

/**
 * @brief Encode a auth_request struct with provided status structure
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 * @param auth_request C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_request_encode_status(uint8_t system_id, uint8_t component_id, mavlink_status_t* _status, mavlink_message_t* msg, const mavlink_auth_request_t* auth_request)
{
    return mavlink_msg_auth_request_pack_status(system_id, component_id, _status, msg,  auth_request->target_system, auth_request->request_type, auth_request->user_id);
}

/**
 * @brief Send a auth_request message
 * @param chan MAVLink channel to send the message
 *
 * @param target_system  Target system ID.
 * @param request_type  Authentication request type.
 * @param user_id  Null-terminated user identifier.
 */
#ifdef MAVLINK_USE_CONVENIENCE_FUNCTIONS

static inline void mavlink_msg_auth_request_send(mavlink_channel_t chan, uint8_t target_system, uint8_t request_type, const char *user_id)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_REQUEST_LEN];
    _mav_put_uint8_t(buf, 0, target_system);
    _mav_put_uint8_t(buf, 1, request_type);
    _mav_put_char_array(buf, 2, user_id, 32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_REQUEST, buf, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#else
    mavlink_auth_request_t packet;
    packet.target_system = target_system;
    packet.request_type = request_type;
    mav_array_memcpy(packet.user_id, user_id, sizeof(char)*32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_REQUEST, (const char *)&packet, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#endif
}

/**
 * @brief Send a auth_request message
 * @param chan MAVLink channel to send the message
 * @param struct The MAVLink struct to serialize
 */
static inline void mavlink_msg_auth_request_send_struct(mavlink_channel_t chan, const mavlink_auth_request_t* auth_request)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    mavlink_msg_auth_request_send(chan, auth_request->target_system, auth_request->request_type, auth_request->user_id);
#else
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_REQUEST, (const char *)auth_request, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#endif
}

#if MAVLINK_MSG_ID_AUTH_REQUEST_LEN <= MAVLINK_MAX_PAYLOAD_LEN
/*
  This variant of _send() can be used to save stack space by re-using
  memory from the receive buffer.  The caller provides a
  mavlink_message_t which is the size of a full mavlink message. This
  is usually the receive buffer for the channel, and allows a reply to an
  incoming message with minimum stack space usage.
 */
static inline void mavlink_msg_auth_request_send_buf(mavlink_message_t *msgbuf, mavlink_channel_t chan,  uint8_t target_system, uint8_t request_type, const char *user_id)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char *buf = (char *)msgbuf;
    _mav_put_uint8_t(buf, 0, target_system);
    _mav_put_uint8_t(buf, 1, request_type);
    _mav_put_char_array(buf, 2, user_id, 32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_REQUEST, buf, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#else
    mavlink_auth_request_t *packet = (mavlink_auth_request_t *)msgbuf;
    packet->target_system = target_system;
    packet->request_type = request_type;
    mav_array_memcpy(packet->user_id, user_id, sizeof(char)*32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_REQUEST, (const char *)packet, MAVLINK_MSG_ID_AUTH_REQUEST_MIN_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_LEN, MAVLINK_MSG_ID_AUTH_REQUEST_CRC);
#endif
}
#endif

#endif

// MESSAGE AUTH_REQUEST UNPACKING


/**
 * @brief Get field target_system from auth_request message
 *
 * @return  Target system ID.
 */
static inline uint8_t mavlink_msg_auth_request_get_target_system(const mavlink_message_t* msg)
{
    return _MAV_RETURN_uint8_t(msg,  0);
}

/**
 * @brief Get field request_type from auth_request message
 *
 * @return  Authentication request type.
 */
static inline uint8_t mavlink_msg_auth_request_get_request_type(const mavlink_message_t* msg)
{
    return _MAV_RETURN_uint8_t(msg,  1);
}

/**
 * @brief Get field user_id from auth_request message
 *
 * @return  Null-terminated user identifier.
 */
static inline uint16_t mavlink_msg_auth_request_get_user_id(const mavlink_message_t* msg, char *user_id)
{
    return _MAV_RETURN_char_array(msg, user_id, 32,  2);
}

/**
 * @brief Decode a auth_request message into a struct
 *
 * @param msg The message to decode
 * @param auth_request C-struct to decode the message contents into
 */
static inline void mavlink_msg_auth_request_decode(const mavlink_message_t* msg, mavlink_auth_request_t* auth_request)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    auth_request->target_system = mavlink_msg_auth_request_get_target_system(msg);
    auth_request->request_type = mavlink_msg_auth_request_get_request_type(msg);
    mavlink_msg_auth_request_get_user_id(msg, auth_request->user_id);
#else
        uint8_t len = msg->len < MAVLINK_MSG_ID_AUTH_REQUEST_LEN? msg->len : MAVLINK_MSG_ID_AUTH_REQUEST_LEN;
        memset(auth_request, 0, MAVLINK_MSG_ID_AUTH_REQUEST_LEN);
    memcpy(auth_request, _MAV_PAYLOAD(msg), len);
#endif
}
