#pragma once

// This structure provides information on the internal member data of
// a PID.  It provides an abstract way to pass PID information around,
// useful for logging and sending mavlink messages.

// It is also used to pass PID information into controllers...

struct AP_PIDInfo {
    float target;
    float actual;
    float error;
    float P;
    float I;
    float D;
    float FF;
    float DFF;
    float Dmod;
    float slew_rate;
    bool limit;
    bool PD_limit;
    bool reset;
    bool I_term_set;

    // Same values as zeroing the object on IEEE754: floats are 0 and flags are false.
    void zero()
    {
        target = 0.0f;
        actual = 0.0f;
        error = 0.0f;
        P = 0.0f;
        I = 0.0f;
        D = 0.0f;
        FF = 0.0f;
        DFF = 0.0f;
        Dmod = 0.0f;
        slew_rate = 0.0f;
        limit = false;
        PD_limit = false;
        reset = false;
        I_term_set = false;
    }
};
