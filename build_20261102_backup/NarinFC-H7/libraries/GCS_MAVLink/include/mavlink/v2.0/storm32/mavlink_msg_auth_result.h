#pragma once
// MESSAGE AUTH_RESULT PACKING

#define MAVLINK_MSG_ID_AUTH_RESULT 60013


typedef struct __mavlink_auth_result_t {
 uint8_t result; /*<  Authentication result.*/
} mavlink_auth_result_t;

#define MAVLINK_MSG_ID_AUTH_RESULT_LEN 1
#define MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN 1
#define MAVLINK_MSG_ID_60013_LEN 1
#define MAVLINK_MSG_ID_60013_MIN_LEN 1

#define MAVLINK_MSG_ID_AUTH_RESULT_CRC 168
#define MAVLINK_MSG_ID_60013_CRC 168



#if MAVLINK_COMMAND_24BIT
#define MAVLINK_MESSAGE_INFO_AUTH_RESULT { \
    60013, \
    "AUTH_RESULT", \
    1, \
    {  { "result", NULL, MAVLINK_TYPE_UINT8_T, 0, 0, offsetof(mavlink_auth_result_t, result) }, \
         } \
}
#else
#define MAVLINK_MESSAGE_INFO_AUTH_RESULT { \
    "AUTH_RESULT", \
    1, \
    {  { "result", NULL, MAVLINK_TYPE_UINT8_T, 0, 0, offsetof(mavlink_auth_result_t, result) }, \
         } \
}
#endif

/**
 * @brief Pack a auth_result message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 *
 * @param result  Authentication result.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_result_pack(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg,
                               uint8_t result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESULT_LEN];
    _mav_put_uint8_t(buf, 0, result);

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#else
    mavlink_auth_result_t packet;
    packet.result = result;

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESULT;
    return mavlink_finalize_message(msg, system_id, component_id, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
}

/**
 * @brief Pack a auth_result message
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 *
 * @param result  Authentication result.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_result_pack_status(uint8_t system_id, uint8_t component_id, mavlink_status_t *_status, mavlink_message_t* msg,
                               uint8_t result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESULT_LEN];
    _mav_put_uint8_t(buf, 0, result);

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#else
    mavlink_auth_result_t packet;
    packet.result = result;

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESULT;
#if MAVLINK_CRC_EXTRA
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#else
    return mavlink_finalize_message_buffer(msg, system_id, component_id, _status, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#endif
}

/**
 * @brief Pack a auth_result message on a channel
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param result  Authentication result.
 * @return length of the message in bytes (excluding serial stream start sign)
 */
static inline uint16_t mavlink_msg_auth_result_pack_chan(uint8_t system_id, uint8_t component_id, uint8_t chan,
                               mavlink_message_t* msg,
                                   uint8_t result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESULT_LEN];
    _mav_put_uint8_t(buf, 0, result);

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), buf, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#else
    mavlink_auth_result_t packet;
    packet.result = result;

        memcpy(_MAV_PAYLOAD_NON_CONST(msg), &packet, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
#endif

    msg->msgid = MAVLINK_MSG_ID_AUTH_RESULT;
    return mavlink_finalize_message_chan(msg, system_id, component_id, chan, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
}

/**
 * @brief Encode a auth_result struct
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param msg The MAVLink message to compress the data into
 * @param auth_result C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_result_encode(uint8_t system_id, uint8_t component_id, mavlink_message_t* msg, const mavlink_auth_result_t* auth_result)
{
    return mavlink_msg_auth_result_pack(system_id, component_id, msg, auth_result->result);
}

/**
 * @brief Encode a auth_result struct on a channel
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param chan The MAVLink channel this message will be sent over
 * @param msg The MAVLink message to compress the data into
 * @param auth_result C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_result_encode_chan(uint8_t system_id, uint8_t component_id, uint8_t chan, mavlink_message_t* msg, const mavlink_auth_result_t* auth_result)
{
    return mavlink_msg_auth_result_pack_chan(system_id, component_id, chan, msg, auth_result->result);
}

/**
 * @brief Encode a auth_result struct with provided status structure
 *
 * @param system_id ID of this system
 * @param component_id ID of this component (e.g. 200 for IMU)
 * @param status MAVLink status structure
 * @param msg The MAVLink message to compress the data into
 * @param auth_result C-struct to read the message contents from
 */
static inline uint16_t mavlink_msg_auth_result_encode_status(uint8_t system_id, uint8_t component_id, mavlink_status_t* _status, mavlink_message_t* msg, const mavlink_auth_result_t* auth_result)
{
    return mavlink_msg_auth_result_pack_status(system_id, component_id, _status, msg,  auth_result->result);
}

/**
 * @brief Send a auth_result message
 * @param chan MAVLink channel to send the message
 *
 * @param result  Authentication result.
 */
#ifdef MAVLINK_USE_CONVENIENCE_FUNCTIONS

static inline void mavlink_msg_auth_result_send(mavlink_channel_t chan, uint8_t result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char buf[MAVLINK_MSG_ID_AUTH_RESULT_LEN];
    _mav_put_uint8_t(buf, 0, result);

    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESULT, buf, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#else
    mavlink_auth_result_t packet;
    packet.result = result;

    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESULT, (const char *)&packet, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#endif
}

/**
 * @brief Send a auth_result message
 * @param chan MAVLink channel to send the message
 * @param struct The MAVLink struct to serialize
 */
static inline void mavlink_msg_auth_result_send_struct(mavlink_channel_t chan, const mavlink_auth_result_t* auth_result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    mavlink_msg_auth_result_send(chan, auth_result->result);
#else
    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESULT, (const char *)auth_result, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#endif
}

#if MAVLINK_MSG_ID_AUTH_RESULT_LEN <= MAVLINK_MAX_PAYLOAD_LEN
/*
  This variant of _send() can be used to save stack space by re-using
  memory from the receive buffer.  The caller provides a
  mavlink_message_t which is the size of a full mavlink message. This
  is usually the receive buffer for the channel, and allows a reply to an
  incoming message with minimum stack space usage.
 */
static inline void mavlink_msg_auth_result_send_buf(mavlink_message_t *msgbuf, mavlink_channel_t chan,  uint8_t result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    char *buf = (char *)msgbuf;
    _mav_put_uint8_t(buf, 0, result);

    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESULT, buf, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#else
    mavlink_auth_result_t *packet = (mavlink_auth_result_t *)msgbuf;
    packet->result = result;

    _mav_finalize_message_chan_send(chan, MAVLINK_MSG_ID_AUTH_RESULT, (const char *)packet, MAVLINK_MSG_ID_AUTH_RESULT_MIN_LEN, MAVLINK_MSG_ID_AUTH_RESULT_LEN, MAVLINK_MSG_ID_AUTH_RESULT_CRC);
#endif
}
#endif

#endif

// MESSAGE AUTH_RESULT UNPACKING


/**
 * @brief Get field result from auth_result message
 *
 * @return  Authentication result.
 */
static inline uint8_t mavlink_msg_auth_result_get_result(const mavlink_message_t* msg)
{
    return _MAV_RETURN_uint8_t(msg,  0);
}

/**
 * @brief Decode a auth_result message into a struct
 *
 * @param msg The message to decode
 * @param auth_result C-struct to decode the message contents into
 */
static inline void mavlink_msg_auth_result_decode(const mavlink_message_t* msg, mavlink_auth_result_t* auth_result)
{
#if MAVLINK_NEED_BYTE_SWAP || !MAVLINK_ALIGNED_FIELDS
    auth_result->result = mavlink_msg_auth_result_get_result(msg);
#else
        uint8_t len = msg->len < MAVLINK_MSG_ID_AUTH_RESULT_LEN? msg->len : MAVLINK_MSG_ID_AUTH_RESULT_LEN;
        memset(auth_result, 0, MAVLINK_MSG_ID_AUTH_RESULT_LEN);
    memcpy(auth_result, _MAV_PAYLOAD(msg), len);
#endif
}
