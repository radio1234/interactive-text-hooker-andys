#pragma once


#define seh_with(...) \
  { \
    __VA_ARGS__ \
    ; \
  }


#define seh_with_eh(_eh, ...) \
  { \
    __VA_ARGS__ \
    ; \
  }
