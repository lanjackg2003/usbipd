/*
 * Copyright (c) 2026-2026, hongquan.li
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Change Logs:
 * Date           Author       Notes
 * 2026-3-24      hongquan.li   add license declaration
 */

/*
 * Virtual CMSIS-DAP v2 Bulk Device
 *
 * Virtual CMSIS-DAP v2 debug probe via USBIP
 * Uses Bulk endpoint transfer, matching real DAPLink v2 behavior
 */

#include <endian.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "DAP.h"
#include "DAP_config.h"
#include "hal/usbip_log.h"
#include "hal/usbip_osal.h"
#include "usbip_common.h"
#include "usbip_control.h"
#include "usbip_devmgr.h"
#include "usbip_util.h"

LOG_MODULE_REGISTER(dap_v2, CONFIG_DAP_LOG_LEVEL);

/**************************************************************************
 * External DAP Lock Wrapper - Defined in hid_dap.c
 **************************************************************************/

extern uint32_t dap_process_command_safety(const uint8_t* request, uint8_t* response);

/*****************************************************************************
 * DAP v2 Device Configuration
 *****************************************************************************/

#define BULK_DAP_VID 0x0D28
#define BULK_DAP_PID 0x0204
#define BULK_DAP_MFR_STR      USBIP_STR_MANUFACTURER
#define BULK_DAP_PRODUCT_STR  USBIP_STR_PRODUCT_BULK
#define BULK_DAP_SERIAL_STR   USBIP_STR_SERIAL
#define BULK_DAP_INTF_STR     USBIP_STR_BULK_INTF

/*
 * Bus speed reported to the host in OP_REP_DEVLIST / OP_REP_IMPORT. The bulk
 * max packet size is derived from it instead of being a separate knob: USB 2.0
 * allows exactly 512 bytes for a high-speed bulk endpoint and at most 64 bytes
 * for a full-speed one. Hosts that validate the configuration descriptor
 * against the reported speed reject any other combination.
 */
#define BULK_DAP_SPEED USB_SPEED_HIGH

#if BULK_DAP_SPEED == USB_SPEED_HIGH
#define BULK_DAP_PACKET_SIZE 512
#elif BULK_DAP_SPEED == USB_SPEED_FULL
#define BULK_DAP_PACKET_SIZE 64
#else
#error "BULK_DAP_SPEED must be USB_SPEED_HIGH or USB_SPEED_FULL."
#endif

/*
 * Advertising MS OS 2.0 is what lets Windows bind WinUSB without an INF, so it
 * is on. Turning it off is the escape hatch for usbip-win2 releases that
 * mishandle the vendor control request carrying the descriptor set: the host
 * then reads the set, resets the port and restarts enumeration forever, which
 * shows up as code 10. 0.9.7.5 is fine; 0.9.8.1 is not. With this off the
 * device enumerates but needs WinUSB installed by hand (Zadig).
 */
#define BULK_DAP_USE_MS_OS_20 1

/* bcdUSB 2.10 is what makes the host ask for the BOS descriptor that carries
 * the MS OS 2.0 platform capability */
#if BULK_DAP_USE_MS_OS_20
#define BULK_DAP_BCD_USB 0x0210
#else
#define BULK_DAP_BCD_USB 0x0200
#endif

/* Compile-time check: BULK_DAP_PACKET_SIZE must not exceed CONFIG_USBIP_URB_DATA_MAX_SIZE */
#if BULK_DAP_PACKET_SIZE > CONFIG_USBIP_URB_DATA_MAX_SIZE
#error "BULK_DAP_PACKET_SIZE exceeds CONFIG_USBIP_URB_DATA_MAX_SIZE."
#endif

/*****************************************************************************
 * BOS Descriptor - Contains Microsoft OS 2.0 Platform Capability
 *****************************************************************************/

#if BULK_DAP_USE_MS_OS_20

#define MS_OS_20_VENDOR_CODE 0x01
#define MS_OS_20_SET_LEN 0xA2
static const uint8_t dap_v2_bos_desc[] = {
    /* BOS Descriptor Header */
    0x05,       /* bLength */
    0x0F,       /* bDescriptorType: BOS */
    0x21, 0x00, /* wTotalLength: 33 bytes */
    0x01,       /* bNumDeviceCaps: 1 */

    /* Microsoft OS 2.0 Platform Capability Descriptor */
    0x1C, /* bLength: 28 bytes */
    0x10, /* bDescriptorType: Device Capability */
    0x05, /* bDevCapabilityType: Platform */
    0x00, /* bReserved */
    /* PlatformCapabilityUUID: d8dd60df-4589-4cc7-9cd2-659d9e648a9f */
    0xDF, 0x60, 0xDD, 0xD8, 0x89, 0x45, 0xC7, 0x4C, 0x9C, 0xD2, 0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F,
    /* Microsoft OS 2.0 specific fields */
    0x00, 0x00, 0x03, 0x06, /* dwWindowsVersion: Windows 8.1 */
    MS_OS_20_SET_LEN, 0x00, /* wMSOSDescriptorSetTotalLength */
    MS_OS_20_VENDOR_CODE,   /* bMS_VendorCode */
    0x00,                   /* bAltEnumCode */
};

/*****************************************************************************
 * Microsoft OS 2.0 Descriptor Set - Follow reference code exactly
 *****************************************************************************/

/* clang-format off */
static const uint8_t dap_v2_msos20_desc[] = {
    // Microsoft OS 2.0 Descriptor Set header (Table 10)
    0x0A, 0x00,  // wLength
    0x00, 0x00,  // wDescriptorType (Set Header)
    0x00, 0x00, 0x03, 0x06,  // dwWindowsVersion: Windows 8.1
    MS_OS_20_SET_LEN, 0x00,  // wTotalLength

    // Microsoft OS 2.0 compatible ID descriptor (Table 13)
    0x14, 0x00,  // wLength
    0x03, 0x00,  // wDescriptorType (Compatible ID)
    'W', 'I', 'N', 'U', 'S', 'B', 0x00, 0x00,  // compatibleID
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // subCompatibleID

    // Microsoft OS 2.0 registry property descriptor (Table 14)
    0x84, 0x00,  // wLength
    0x04, 0x00,  // wDescriptorType (Registry Property)
    0x07, 0x00,  // wPropertyDataType: REG_MULTI_SZ
    0x2A, 0x00,  // wPropertyNameLength (42 bytes)
    // PropertyName: DeviceInterfaceGUIDs
    'D',0,'e',0,'v',0,'i',0,'c',0,'e',0,'I',0,'n',0,'t',0,'e',0,'r',0,'f',0,'a',0,'c',0,'e',0,'G',0,'U',0,'I',0,'D',0,'s',0, 0,0,
    0x50, 0x00,  // wPropertyDataLength (80 bytes)
    // PropertyData: CMSIS-DAP V2 GUID
    '{',0,'C',0,'D',0,'B',0,'3',0,'B',0,'5',0,'A',0,'D',0,'-',0,'2',0,'9',0,'3',0,'B',0,'-',0,'4',0,'6',0,'6',0,'3',0,'-',0,'A',0,'A',0,'3',0,'6',0,'-',0,'1',0,'A',0,'A',0,'E',0,'4',0,'6',0,'4',0,'6',0,'3',0,'7',0,'7',0,'6',0,'}',0, 0,0, 0,0,
};
/* clang-format on */

/* The lengths below are hand written into the byte arrays and are also what the
 * host is told to expect, so a miscount silently truncates the reply instead of
 * failing anywhere visible */
_Static_assert(sizeof(dap_v2_bos_desc) == 33, "BOS wTotalLength disagrees with the array");
_Static_assert(sizeof(dap_v2_msos20_desc) == MS_OS_20_SET_LEN,
               "MS OS 2.0 wTotalLength disagrees with the array");

#endif /* BULK_DAP_USE_MS_OS_20 */

/*****************************************************************************
 * USB Descriptors
 *****************************************************************************/

static const struct usb_device_descriptor dap_v2_dev_desc = {
    .bLength = USB_DT_DEVICE_SIZE,
    .bDescriptorType = USB_DT_DEVICE,
    .bcdUSB = BULK_DAP_BCD_USB,
    .bDeviceClass = 0x00, /* Defined at interface level */
    .bDeviceSubClass = 0x00,
    .bDeviceProtocol = 0x00,
    .bMaxPacketSize0 = 64,
    .idVendor = BULK_DAP_VID,
    .idProduct = BULK_DAP_PID,
    .bcdDevice = 0x0100,
    .iManufacturer = 1,
    .iProduct = 2,
    .iSerialNumber = 3,
    .bNumConfigurations = 1,
};

/* DAP v2 Simple Config Descriptor - Single Interface */
struct dap_v2_config_desc
{
    struct usb_config_descriptor config;
    struct usb_interface_descriptor dap_intf;
    struct usb_endpoint_descriptor dap_ep_out;
    struct usb_endpoint_descriptor dap_ep_in;
} __attribute__((packed));

static const struct dap_v2_config_desc dap_v2_cfg_desc = {
    .config =
        {
            .bLength = USB_DT_CONFIG_SIZE,
            .bDescriptorType = USB_DT_CONFIG,
            .wTotalLength = sizeof(struct dap_v2_config_desc),
            .bNumInterfaces = 1,
            .bConfigurationValue = 1,
            .iConfiguration = 0,
            .bmAttributes = 0x80,
            .bMaxPower = 250, /* 500mA */
        },

    /* DAP v2 Interface */
    .dap_intf =
        {
            .bLength = USB_DT_INTERFACE_SIZE,
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bAlternateSetting = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = 0xFF, /* Vendor Specific */
            .bInterfaceSubClass = 0x00,
            .bInterfaceProtocol = 0x00,
            .iInterface = 4,
        },
    .dap_ep_out =
        {
            .bLength = USB_DT_ENDPOINT_SIZE,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 0x01,
            .bmAttributes = 0x02, /* Bulk */
            .wMaxPacketSize = BULK_DAP_PACKET_SIZE,
            .bInterval = 0,
        },
    .dap_ep_in =
        {
            .bLength = USB_DT_ENDPOINT_SIZE,
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 0x81,
            .bmAttributes = 0x02, /* Bulk */
            .wMaxPacketSize = BULK_DAP_PACKET_SIZE,
            .bInterval = 0,
        },
};

/*****************************************************************************
 * String Descriptors
 *****************************************************************************/

/* clang-format off */
static const uint8_t string0_desc[] = { 0x04, USB_DT_STRING, 0x09, 0x04 };
/* clang-format on */

static uint8_t s_string1_desc[2 + ((sizeof(BULK_DAP_MFR_STR) - 1) * 2)] = {0};
static uint8_t s_string2_desc[2 + ((sizeof(BULK_DAP_PRODUCT_STR) - 1) * 2)] = {0};
static uint8_t s_string3_desc[2 + ((sizeof(BULK_DAP_SERIAL_STR) - 1) * 2)] = {0};
static uint8_t s_string4_desc[2 + ((sizeof(BULK_DAP_INTF_STR) - 1) * 2)] = {0};
static const uint8_t* dap_v2_string_descs[] = {
    s_string1_desc,
    s_string2_desc,
    s_string3_desc,
    s_string4_desc,
};

/*****************************************************************************
 * DAP v2 Device State
 *****************************************************************************/

struct virtual_dap_v2
{
    struct usbip_usb_device udev;
    struct usb_control_context ctrl_ctx;

    int exported;
    struct usbip_connection* conn;

    /* DAP Response Buffer - protected by response_lock */
    struct osal_mutex response_lock;
    uint8_t response[BULK_DAP_PACKET_SIZE];
    size_t response_len;
    int response_pending;
};

static struct virtual_dap_v2 vdap_v2;

/*****************************************************************************
 * DAP Command Processing
 *****************************************************************************/

static void dap_v2_process_command(const void* data, size_t len)
{
    LOG_HEX_DBG("[CMD] %zu bytes:", (const uint8_t*)data, len, len);

    if (DAP_GetPacketSize() != BULK_DAP_PACKET_SIZE)
    {
        DAP_SetPacketSize(BULK_DAP_PACKET_SIZE);
    }

    osal_mutex_lock(&vdap_v2.response_lock);
    /* Process command with global DAP lock */
    vdap_v2.response_len = dap_process_command_safety((const uint8_t*)data, vdap_v2.response) & 0xFFFF;
    vdap_v2.response_pending = 1;
    osal_mutex_unlock(&vdap_v2.response_lock);

    LOG_HEX_DBG("[RSP] %zu bytes:", vdap_v2.response, vdap_v2.response_len, vdap_v2.response_len);
}

/*****************************************************************************
 * URB Processing
 *****************************************************************************/

static int vdap_v2_handle_urb(struct usbip_device_driver* driver,
                              const struct usbip_header* urb_cmd, struct usbip_header* urb_ret,
                              void** data_out, size_t* data_len, const void* urb_data,
                              size_t urb_data_len)
{
    uint32_t ep;
    int ret;
    size_t response_len = 0;
    int has_response = 0;

    (void)driver;
    ret = 1;

    if (!vdap_v2.exported)
    {
        memset(urb_ret, 0, sizeof(*urb_ret));
        urb_ret->base.command = USBIP_RET_SUBMIT;
        urb_ret->u.ret_submit.status = -ENODEV;
        return 1;
    }

    memset(urb_ret, 0, sizeof(*urb_ret));
    urb_ret->base.command = USBIP_RET_SUBMIT;
    urb_ret->base.seqnum = urb_cmd->base.seqnum;
    urb_ret->base.devid = urb_cmd->base.devid;
    urb_ret->base.direction = urb_cmd->base.direction;
    urb_ret->base.ep = urb_cmd->base.ep;
    ep = urb_cmd->base.ep;

    switch (urb_cmd->base.command)
    {
        case USBIP_CMD_SUBMIT:
            if (ep == 0)
            {
                /* Control endpoint */
                const struct usb_setup_packet* setup =
                    (const struct usb_setup_packet*)urb_cmd->u.cmd_submit.setup;

                /* Log all control requests */
                LOG_DBG("Control: bmRequestType=0x%02x bRequest=0x%02x wValue=0x%04x wIndex=0x%04x "
                        "wLength=%d",
                        setup->bmRequestType, setup->bRequest, setup->wValue, setup->wIndex,
                        setup->wLength);

#if BULK_DAP_USE_MS_OS_20
                /* Check if this is a Microsoft OS 2.0 vendor request */
                if (USB_SETUP_TYPE(setup) == 0x02 && /* Vendor type */
                    USB_SETUP_IS_IN(setup))
                {
                    LOG_DBG("Vendor IN request: bRequest=0x%02x wIndex=0x%04x wValue=0x%04x",
                            setup->bRequest, setup->wIndex, setup->wValue);

                    if (setup->bRequest == MS_OS_20_VENDOR_CODE)
                    {
                        /* MS_OS_20_DESCRIPTOR_INDEX */
                        if (setup->wIndex == 0x0007)
                        {
                            LOG_DBG("MS OS 2.0 Descriptor request");
                            *data_out = osal_malloc(sizeof(dap_v2_msos20_desc));
                            if (*data_out)
                            {
                                memcpy(*data_out, dap_v2_msos20_desc, sizeof(dap_v2_msos20_desc));
                                *data_len = sizeof(dap_v2_msos20_desc);
                                if (*data_len > setup->wLength)
                                {
                                    *data_len = setup->wLength;
                                }
                                urb_ret->u.ret_submit.actual_length = *data_len;
                                urb_ret->u.ret_submit.status = 0;
                            }
                            else
                            {
                                urb_ret->u.ret_submit.status = -ENOMEM;
                                urb_ret->u.ret_submit.actual_length = 0;
                            }
                            break;
                        }
                        /* MS_OS_20_SET_ALT_ENUMERATION */
                        else if (setup->wIndex == 0x0008)
                        {
                            LOG_INF("MS OS 2.0 Alt Enumeration request");
                            *data_out = NULL;
                            *data_len = 0;
                            urb_ret->u.ret_submit.actual_length = 0;
                            urb_ret->u.ret_submit.status = 0;
                            break;
                        }
                    }
                }
#endif /* BULK_DAP_USE_MS_OS_20 */

                if (USB_SETUP_IS_IN(setup))
                {
                    int ctrl_ret =
                        usb_control_handle_setup(setup, &vdap_v2.ctrl_ctx, data_out, data_len);
                    if (ctrl_ret == USB_CONTROL_STALL)
                    {
                        LOG_DBG("Control IN stalled: bRequest=0x%02x wValue=0x%04x",
                                setup->bRequest, setup->wValue);
                        urb_ret->u.ret_submit.status = -EPIPE;
                        urb_ret->u.ret_submit.actual_length = 0;
                    }
                    else if (ctrl_ret == USB_CONTROL_ERROR)
                    {
                        /* Reporting a zero length success here makes the host treat the
                         * descriptor as empty and restart enumeration, so fail explicitly */
                        LOG_ERR("Control IN failed: bRequest=0x%02x wValue=0x%04x",
                                setup->bRequest, setup->wValue);
                        urb_ret->u.ret_submit.status = -ENOMEM;
                        urb_ret->u.ret_submit.actual_length = 0;
                    }
                    else
                    {
                        urb_ret->u.ret_submit.actual_length = *data_len;
                        urb_ret->u.ret_submit.status = 0;
                    }
                }
                else
                {
                    *data_out = NULL;
                    *data_len = 0;
                    urb_ret->u.ret_submit.actual_length = 0;
                    urb_ret->u.ret_submit.status = 0;
                }
            }
            /* DAP v2 Bulk OUT (EP1) */
            else if (ep == 1 && urb_cmd->base.direction == USBIP_DIR_OUT)
            {
                *data_out = NULL;
                *data_len = 0;

                if (urb_data && urb_data_len > 0)
                {
                    dap_v2_process_command(urb_data, urb_data_len);
                }
                urb_ret->u.ret_submit.actual_length = urb_data_len;
                urb_ret->u.ret_submit.status = 0;
            }
            /* DAP v2 Bulk IN (EP1) */
            else if (ep == 1 && urb_cmd->base.direction == USBIP_DIR_IN)
            {
                /* Check and consume response with lock held */
                osal_mutex_lock(&vdap_v2.response_lock);
                if (vdap_v2.response_pending)
                {
                    has_response = 1;
                    response_len = vdap_v2.response_len;
                    *data_out = osal_malloc(response_len);
                    if (*data_out)
                    {
                        memcpy(*data_out, vdap_v2.response, response_len);
                        *data_len = response_len;
                        urb_ret->u.ret_submit.actual_length = response_len;
                        urb_ret->u.ret_submit.status = 0;
                        vdap_v2.response_pending = 0;
                    }
                    else
                    {
                        urb_ret->u.ret_submit.status = -ENOMEM;
                        urb_ret->u.ret_submit.actual_length = 0;
                    }
                }
                osal_mutex_unlock(&vdap_v2.response_lock);

                if (has_response)
                {
                    LOG_DBG("IN: %zu bytes", response_len);
                }
                else
                {
                    /* Bulk endpoint has no data, return NAK (return 0 bytes to let host retry) */
                    *data_out = NULL;
                    *data_len = 0;
                    urb_ret->u.ret_submit.status = 0;
                    urb_ret->u.ret_submit.actual_length = 0;
                    /* Delay 1ms when no response to optimize PyOCD response */
                    osal_sleep_ms(1);
                }
            }
            else
            {
                *data_out = NULL;
                *data_len = 0;
                urb_ret->u.ret_submit.status = 0;
                urb_ret->u.ret_submit.actual_length = 0;
            }
            break;

        case USBIP_CMD_UNLINK:
            urb_ret->base.command = USBIP_RET_UNLINK;
            urb_ret->u.ret_unlink.status = 0;
            break;

        default:
            LOG_ERR("Unknown command: 0x%04x", urb_cmd->base.command);
            ret = -1;
            break;
    }

    return ret;
}

/*****************************************************************************
 * Device Enumeration Interface
 *****************************************************************************/

static int vdap_v2_get_device_count(struct usbip_device_driver* driver)
{
    (void)driver;

    if (vdap_v2.udev.busid[0] == '\0')
    {
        return 0;
    }

    return 1;
}

static int vdap_v2_get_device_by_index(struct usbip_device_driver* driver, int index,
                                       struct usbip_usb_device* device)
{
    (void)driver;

    if (index != 0 || vdap_v2.udev.busid[0] == '\0')
    {
        return -1;
    }

    memcpy(device, &vdap_v2.udev, sizeof(*device));

    return 0;
}

static const struct usbip_usb_device* vdap_v2_get_device(struct usbip_device_driver* driver,
                                                         const char* busid)
{
    (void)driver;

    if (strcmp(vdap_v2.udev.busid, busid) == 0)
    {
        return &vdap_v2.udev;
    }
    return NULL;
}

static int vdap_v2_get_interface(struct usbip_device_driver* driver, int index,
                                 struct usbip_usb_interface* iface)
{
    (void)driver;

    if (index != 0 || iface == NULL)
    {
        return -1;
    }

    iface->bInterfaceClass = dap_v2_cfg_desc.dap_intf.bInterfaceClass;
    iface->bInterfaceSubClass = dap_v2_cfg_desc.dap_intf.bInterfaceSubClass;
    iface->bInterfaceProtocol = dap_v2_cfg_desc.dap_intf.bInterfaceProtocol;
    iface->padding = 0;

    return 0;
}

static int vdap_v2_export_device(struct usbip_device_driver* driver, const char* busid,
                                 struct usbip_connection* conn)
{
    (void)driver;

    if (strcmp(vdap_v2.udev.busid, busid) != 0 || vdap_v2.exported)
    {
        return -1;
    }

    vdap_v2.exported = 1;
    vdap_v2.conn = conn;

    LOG_INF("Exported: %s", busid);
    return 0;
}

static int vdap_v2_unexport_device(struct usbip_device_driver* driver, const char* busid)
{
    (void)driver;

    if (strcmp(vdap_v2.udev.busid, busid) != 0)
    {
        return -1;
    }

    vdap_v2.exported = 0;
    vdap_v2.conn = NULL;

    LOG_INF("Unexported: %s", busid);
    return 0;
}

/*****************************************************************************
 * Initialization and Cleanup
 *****************************************************************************/

static int vdap_v2_init(struct usbip_device_driver* driver)
{
    int ret;
    char serial_ascii[sizeof(BULK_DAP_SERIAL_STR)] = {0};

    (void)driver;

    memset(&vdap_v2, 0, sizeof(vdap_v2));

    /* Initialize response mutex */
    ret = osal_mutex_init(&vdap_v2.response_lock);
    if (ret != OSAL_OK)
    {
        LOG_ERR("Failed to initialize DAP v2 response mutex");
        return -1;
    }

    strncpy(vdap_v2.udev.path, "/sys/devices/platform/virtual-dap-v2", SYSFS_PATH_MAX - 1);
    strncpy(vdap_v2.udev.busid, "2-2", SYSFS_BUS_ID_SIZE - 1);
    vdap_v2.udev.busnum = 1;
    vdap_v2.udev.devnum = 4;
    vdap_v2.udev.speed = BULK_DAP_SPEED;
    vdap_v2.udev.idVendor = dap_v2_dev_desc.idVendor;
    vdap_v2.udev.idProduct = dap_v2_dev_desc.idProduct;
    vdap_v2.udev.bcdDevice = dap_v2_dev_desc.bcdDevice;
    vdap_v2.udev.bDeviceClass = dap_v2_dev_desc.bDeviceClass;
    vdap_v2.udev.bDeviceSubClass = dap_v2_dev_desc.bDeviceSubClass;
    vdap_v2.udev.bDeviceProtocol = dap_v2_dev_desc.bDeviceProtocol;
    vdap_v2.udev.bConfigurationValue = 1;
    vdap_v2.udev.bNumConfigurations = dap_v2_dev_desc.bNumConfigurations;
    vdap_v2.udev.bNumInterfaces = 1;

    vdap_v2.ctrl_ctx = (struct usb_control_context)USB_CONTROL_CONTEXT_INIT(
        &dap_v2_dev_desc, &dap_v2_cfg_desc, sizeof(dap_v2_cfg_desc));

    ascii_string_to_utf16le(s_string1_desc, sizeof(s_string1_desc), BULK_DAP_MFR_STR);
    ascii_string_to_utf16le(s_string2_desc, sizeof(s_string2_desc), BULK_DAP_PRODUCT_STR);
    ascii_string_to_utf16le(s_string3_desc, sizeof(s_string3_desc), BULK_DAP_SERIAL_STR);
    ascii_string_to_utf16le(s_string4_desc, sizeof(s_string4_desc), BULK_DAP_INTF_STR);

    if (usbip_desc_get_serial_ascii(serial_ascii, sizeof(serial_ascii)))
    {
        ascii_string_to_utf16le(s_string3_desc, sizeof(s_string3_desc), serial_ascii);
        LOG_INF("Bulk DAP serial descriptor overridden by platform provider");
    }
    vdap_v2.ctrl_ctx.lang_id_desc = string0_desc;
    vdap_v2.ctrl_ctx.string_descs = dap_v2_string_descs;
    vdap_v2.ctrl_ctx.num_strings = 4;
    vdap_v2.ctrl_ctx.num_configs = 1;
#if BULK_DAP_USE_MS_OS_20
    vdap_v2.ctrl_ctx.bos_desc = dap_v2_bos_desc;
    vdap_v2.ctrl_ctx.bos_desc_len = sizeof(dap_v2_bos_desc);
#endif
    DAP_Setup();

    LOG_INF("Init (VID=%04x PID=%04x) Bulk mode, %s speed, %d byte endpoints, MS OS 2.0 %s",
            BULK_DAP_VID, BULK_DAP_PID, BULK_DAP_SPEED == USB_SPEED_HIGH ? "high" : "full",
            BULK_DAP_PACKET_SIZE, BULK_DAP_USE_MS_OS_20 ? "on" : "off");
    return 0;
}

static void vdap_v2_cleanup(struct usbip_device_driver* driver)
{
    (void)driver;

    /* Destroy response mutex */
    osal_mutex_destroy(&vdap_v2.response_lock);
    memset(&vdap_v2, 0, sizeof(vdap_v2));
}

struct usbip_device_driver virtual_dap_v2_driver = {
    .name = "virtual-dap-v2",
    .get_device_count = vdap_v2_get_device_count,
    .get_device_by_index = vdap_v2_get_device_by_index,
    .get_device = vdap_v2_get_device,
    .get_interface = vdap_v2_get_interface,
    .export_device = vdap_v2_export_device,
    .unexport_device = vdap_v2_unexport_device,
    .handle_urb = vdap_v2_handle_urb,
    .init = vdap_v2_init,
    .cleanup = vdap_v2_cleanup,
};

/*****************************************************************************
 * Auto-Register on Program Startup
 *****************************************************************************/

void __attribute__((used)) bulk_dap_driver_register(void)
{
    usbip_register_driver(&virtual_dap_v2_driver);
}