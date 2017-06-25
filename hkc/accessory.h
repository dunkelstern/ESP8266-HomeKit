#ifndef accessory_h__included
#define accessory_h__included

#include <esp_common.h>
#include <cJSON.h>

typedef void (*acc_cb)(int aid, int iid, cJSON *value, int mode);

#define BOOLEAN "bool"
#define STRING  "string"
#define INT     "int"

/******************************************************************************/
//brand name
#define APPLE   "000000%02X-0000-1000-8000-0026BB765291"

//sType name
#define LIGHTBULB_S                             0x43
#define SWITCH_S                                0x49
#define THERMOSTAT_S                            0x4A
#define GARAGE_DOOR_OPENER_S                    0x41
#define ACCESSORY_INFORMATION_S                 0x3E
#define FAN_S                                   0x40
#define OUTLET_S                                0x47
#define LOCK_MECHANISM_S                        0x45
#define LOCK_MANAGEMENT_S                       0x44

//cType name                                    Type    //mxlen format  read/write/event
#define ADMIN_ONLY_ACCESS_C                     0x01
#define AUDIO_FEEDBACK_C                        0x05
#define BRIGHTNESS_C                            0x08    //n/a   int     rwe
#define COOLING_THRESHOLD_C                     0x0D
#define CURRENT_DOOR_STATE_C                    0x0E
#define CURRENT_LOCK_MECHANISM_STATE_C          0x1D
#define CURRENT_RELATIVE_HUMIDITY_C             0x10
#define CURRENT_TEMPERATURE_C                   0x11
#define HEATING_THRESHOLD_C                     0x12
#define HUE_C                                   0x13
#define IDENTIFY_C                              0x14    //  1   boolean w
#define LOCK_MANAGEMENT_AUTO_SECURE_TIMEOUT_C   0x1A
#define LOCK_MANAGEMENT_CONTROL_POINT_C         0x19
#define LOCK_MECHANISM_LAST_KNOWN_ACTION_C      0x1C
#define LOGS_C                                  0x1F
#define MANUFACTURER_C                          0x20    //255   string  r
#define MODEL_C                                 0x21    //255   string  r
#define MOTION_DETECTED_C                       0x22
#define NAME_C                                  0x23    //255   string  r
#define OBSTRUCTION_DETECTED_C                  0x24
#define OUTLET_IN_USE_C                         0x26
#define POWER_STATE_C                           0x25    //  1   boolean rwe
#define ROTATION_DIRECTION_C                    0x28
#define ROTATION_SPEED_C                        0x29
#define SATURATION_C                            0x2F
#define SERIAL_NUMBER_C                         0x30    //255   string  r
#define TARGET_DOORSTATE_C                      0x32
#define TARGET_LOCK_MECHANISM_STATE_C           0x1E
#define TARGET_RELATIVE_HUMIDITY_C              0x34
#define TARGET_TEMPERATURE_C                    0x35
#define TEMPERATURE_UNITS_C                     0x36
#define VERSION_C                               0x37
#define CURRENTHEATINGCOOLING_C                 0x0F
#define TARGETHEATINGCOOLING_C                  0x33


void ICACHE_FLASH_ATTR
json_init(void *arg);

cJSON * ICACHE_FLASH_ATTR
initAccessories();

cJSON * ICACHE_FLASH_ATTR
addAccessory(cJSON *accs, int aid);

cJSON * ICACHE_FLASH_ATTR
addService(cJSON *services, int iid, char *brand, int sType);

void ICACHE_FLASH_ATTR
addCharacteristic(cJSON *characteristics, int aid, int iid, char *brand, int cType, char *valuestring, acc_cb change_cb);

#endif