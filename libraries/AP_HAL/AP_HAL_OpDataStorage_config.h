#pragma once

/*
  When set (e.g. NarinFC-H7 hwdef), mission / rally / fence data are kept only in
  RAM-backed buffers inside StorageAccess — not in FRAM hal.storage and not on
  mission.stg / fence.stg. Home is not written to mission slot 0.

  Parameter storage (MIS_TOTAL, RALLY_TOTAL, FENCE_TOTAL, etc.) may still update
  when missions/rally/fence are changed in RAM; those live in the parameter
  region unless separately managed.
 */

#ifndef HAL_STORAGE_OP_DATA_PERSIST_DISABLED
#define HAL_STORAGE_OP_DATA_PERSIST_DISABLED 0
#endif
