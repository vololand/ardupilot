#pragma once
// MESSAGE AUTH_RESPONSE PACKING

#define MAVLINK_MSG_ID_AUTH_RESPONSE 60012


typedef struct __mavlink_auth_response_t {
 uint32_t timestamp; /*< [ms] Echo of AUTH_CHALLENGE timestamp.*/
 uint8_t response[32]; /*<  SHA-256(H + challenge) response digest.*/
} mavlink_auth_response_t;

#define MAVLINK_MSG_ID_AUTH_RESPONSE_LEN 36
#define MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN 36
#define MAVLINK_MSG_ID_60012_LEN 36
#define MAVLINK_MSG_ID_60012_MIN_LEN 36

#define MAVLINK_MSG_ID_AUTH_RESPONSE_CRC 132
#define MAVLINK_MSG_ID_60012_CRC 132

#define MAVLINK_MSG_AUTH_RESPONSE_FIELD_RESPONSE_LEN 32

#if MAVLINK_COMMAND_24BIT
#define MAVLINK_MESSAGE_INFO_AUTH_RESPONSE { \
    60012, \
    "AUTH_RESPONSE", \
    2, \
    {  { "response", NULL, MAVLINK_TYPE_UINT8_T, 32, 4, offsetof(mavlink_auth_response_t, response) }, \
         { "timestamp", NULL, MAVLINK_TYPE_UINT32_T, 0, 0, offsetof(mavlink_auth_response_t, timestamp) }, \
         } \
}
#else
#define MAVLINK_MESSAGE_INFO_AUTH_RESPONSE { \
    "AUTH_RESPONSE", \
    2, \
    {  { "response", NULL, MAVLINK_TYPE_UINT8_T, 32, 4, offsetof(mavlink_auth_response_t, response) }, \
         { "timestamp", NULL, MAVLINK_TYPE_UINT32_T, 0, 0, offsetof(mavlink_auth_response_t, timestamp) }, \
         } \
}
#endif

/**
 * @brief Pack a auth_response message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 *
 * @param response  SHA-256(H + challenge) response digest.
 * @param timestamp [ms] Echo of AUTH_CHALLENGE timestamp.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_response_pack(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg,
                               const uint8_t *response, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESPONSE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, response, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#else
    mavlink_auth_response_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.response, response, sizeof(uint8_t)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESPONSE;
    return mavlink_finalize_message(msg, system_id, component_id, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
}

/**
 * @brief Pack a auth_response message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 *
 * @param response  SHA-256(H + challenge) response digest.
 * @param timestamp [ms] Echo of AUTH_CHALLENGE timestamp.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_response_pack_status(uint8_t system_id, uint8_t component_id, mavlink_status_t *_status, mavlink_message_t* msg,
                               const uint8_t *response, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESPONSE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, response, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#else
    mavlink_auth_response_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.response, response, sizeof(uint8_t)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESPONSE;
#if MAVLINK_CRC_EXTRA
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#else
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#endif
}

/**
 * @brief Pack a auth_response message on a channel
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param response  SHA-256(H + challenge) response digest.
 * @param timestamp [ms] Echo of AUTH_CHALLENGE timestamp.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_response_pack_chan(uint8_t system_id, uint8_t component_id, uint8_t chan,
                               mavlink_message_t* msg,
                                   const uint8_t *response,uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESPONSE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, response, 32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#else
    mavlink_auth_response_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.response, response, sizeof(uint8_t)*32);
        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESPONSE;
    return mavlink_finalize_message_chan(msg, system_id, component_id, chan, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
}

/**
 * @brief Encode a auth_response struct
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 * @param auth_response C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_response_encode(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg, const mavlink_auth_response_t* auth_response)
{
    return mavlink_msg_auth_response_pack(system_id, component_id, msg, auth_response->response, auth_response->timestamp);
}

/**
 * @brief Encode a auth_response struct on a channel
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param auth_response C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_response_encode_chan(uint8_t system_id, uint8_t component_id, uint8_t chan, mavlink_message_t* msg, const mavlink_auth_response_t* auth_response)
{
    return mavlink_msg_auth_response_pack_chan(system_id, component_id, chan, msg, auth_response->response, auth_response->timestamp);
}

/**
 * @brief Encode a auth_response struct with provided status structure
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 * @param auth_response C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_response_encode_status(uint8_t system_id, uint8_t component_id, mavlink_status_t* _status, mavlink_message_t* msg, const mavlink_auth_response_t* auth_response)
{
    return mavlink_msg_auth_response_pack_status(system_id, component_id, _status, msg,  auth_response->response, auth_response->timestamp);
}

/**
 * @brief Send a auth_response message
 * @param chan MAVLink channel to send the message
 *
 * @param response  SHA-256(H + challenge) response digest.
 * @param timestamp [ms] Echo of AUTH_CHALLENGE timestamp.
 */
#ifdef MAVLINK_USE_CONVENIENCE_FUNCTIONS

static inline void mavlink_msg_auth_response_send(mavlink_channel_t chan, const uint8_t *response, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESPONSE_LEN];
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, response, 32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESPONSE, buf, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#else
    mavlink_auth_response_t packet;
    packet.timestamp = timestamp;
    mav_array_memcpy(packet.response, response, sizeof(uint8_t)*32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESPONSE, (const char *)&packet, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#endif
}

/**
 * @brief Send a auth_response message
 * @param chan MAVLink channel to send the message
 * @param struct The MAVLink struct to serialize
 */
static inline void mavlink_msg_auth_response_send_struct(mavlink_channel_t chan, const mavlink_auth_response_t* auth_response)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    mavlink_msg_auth_response_send(chan, auth_response->response, auth_response->timestamp);
#else
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESPONSE, (const char *)auth_response, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#endif
}

#if MAVLINK_MSG_ID_AUTH_RESPONSE_LEN <= MAVLINK_MAX_PAYLOAD_LEN
/*
  This variant of _send() can be used to save stack space by re-using
  memory from the receive buffer.  The caller provides a
  mavlink_message_t which is the size of a full mavlink message. This
  is usually the receive buffer for the channel, and allows a reply to an
  incoming message with minimum stack space usage.
 */
static inline void mavlink_msg_auth_response_send_buf(mavlink_message_t *msgbuf, mavlink_channel_t chan,  const uint8_t *response, uint32_t timestamp)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char *buf = (char *)msgbuf;
    _mav_put_uint32_t(buf, 0, timestamp);
    _mav_put_uint8_t_array(buf, 4, response, 32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESPONSE, buf, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#else
    mavlink_auth_response_t *packet = (mavlink_auth_response_t *)msgbuf;
    packet->timestamp = timestamp;
    mav_array_memcpy(packet->response, response, sizeof(uint8_t)*32);
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESPONSE, (const char *)packet, MAVLINK_MSG_ID_AUTH_RESPONSE_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN, MAVLINK_MSG_ID_AUTH_RESPONSE_CRC);
#endif
}
#endif

#endif

// MESSAGE AUTH_RESPONSE UNPACKING


/**
 * @brief Get field response from auth_response message
 *
 * @return  SHA-256(H + challenge) response digest.
 */
static inline uint16_t mavlink_msg_auth_response_get_response(const mavlink_message_t* msg, uint8_t *response)
{
    return _MAV_RETURN_uint8_t_array(msg, response, 32,  4);
}

/**
 * @brief Get field timestamp from auth_response message
 *
 * @return [ms] Echo of AUTH_CHALLENGE timestamp.
 */
static inline uint32_t mavlink_msg_auth_response_get_timestamp(const mavlink_message_t* msg)
{
    return _MAV_RETURN_uint32_t(msg,  0);
}

/**
 * @brief Decode a auth_response message into a struct
 *
 * @param msg The message to decode
 * @param auth_response C-struct to decode the message contents into
 */
static inline void mavlink_msg_auth_response_decode(const mavlink_message_t* msg, mavlink_auth_response_t* auth_response)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    auth_response->timestamp = mavlink_msg_auth_response_get_timestamp(msg);
    mavlink_msg_auth_response_get_response(msg, auth_response->response);
#else
        uint8_t len = msg->len < MAVLINK_MSG_ID_AUTH_RESPONSE_LEN? msg->len : MAVLINK_MSG_ID_AUTH_RESPONSE_LEN;
        memset(auth_response, 0, MAVLINK_MSG_ID_AUTH_RESPONSE_LEN);
    memcpy(auth_response, _MAV_PAYLOAD(msg), len);
#endif
}
