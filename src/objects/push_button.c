/*
 * Copyright 2020-2023 AVSystem <avsystem@avsystem.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <stdbool.h>

#include <anjay/anjay.h>
#include <anjay/ipso_objects.h>
#include <avsystem/commons/avs_defs.h>
#include <avsystem/commons/avs_list.h>
#include <avsystem/commons/avs_memory.h>

#include <zephyr/devicetree.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include "objects.h"
#include "utils.h"

LOG_MODULE_REGISTER(anjay_zephyr_push_button);

#define BUTTON_CHANGE_WORKS_NUM 256

struct button_instance {
    anjay_t *anjay;
    struct anjay_zephyr_ipso_button_instance *button;
    struct gpio_callback push_button_callback;
};

static struct button_instance *buttons;

struct change_button_state_work {
    bool reserved;
    struct k_work work;
    anjay_t *anjay;
    anjay_iid_t iid;
    bool state;
};

static struct change_button_state_work
        button_change_works[BUTTON_CHANGE_WORKS_NUM];
static size_t last_work_slot;

static void button_change_state_handler(struct k_work *_work) {
    struct change_button_state_work *work =
            CONTAINER_OF(_work, struct change_button_state_work, work);
    anjay_ipso_button_update(work->anjay, work->iid, work->state);
    work->reserved = false;
}

static void button_state_changed(const struct device *dev,
                                 struct gpio_callback *cb,
                                 uint32_t pins) {
    (void) pins;
    struct button_instance *glue =
            AVS_CONTAINER_OF(cb, struct button_instance, push_button_callback);
    struct change_button_state_work *work = NULL;

    for (int i = 0; i < BUTTON_CHANGE_WORKS_NUM; i++) {
        int slot_num = (last_work_slot + i + 1) % BUTTON_CHANGE_WORKS_NUM;

        if (!button_change_works[slot_num].reserved) {
            last_work_slot = slot_num;

            work = &button_change_works[slot_num];
            work->reserved = true;
            work->anjay = glue->anjay;
            work->state = (bool) gpio_pin_get(dev, glue->button->gpio_pin);
            work->iid = (anjay_iid_t) ((size_t) (glue - buttons));

            k_work_init(&work->work, button_change_state_handler);

            if (_anjay_zephyr_k_work_submit(&work->work) == 1) {
                return;
            }

            break;
        }
    }

    LOG_ERR("Could not schedule the work");
}

static int configure_push_button(anjay_t *anjay,
                                 const struct device *dev,
                                 int gpio_pin,
                                 int gpio_flags,
                                 anjay_iid_t iid,
                                 struct button_instance *glue) {
    if (!device_is_ready(dev) || gpio_pin_configure(dev, gpio_pin, gpio_flags)
            || gpio_pin_interrupt_configure(dev, gpio_pin,
                                            GPIO_INT_EDGE_BOTH)) {
        return -1;
    }

    char application_type[40];

    sprintf(application_type, "Button %d", iid);
    if (anjay_ipso_button_instance_add(anjay, iid, application_type)) {
        return -1;
    }

    (void) anjay_ipso_button_update(anjay, iid, gpio_pin_get(dev, gpio_pin));

    gpio_init_callback(&glue->push_button_callback, button_state_changed,
                       BIT(gpio_pin));
    glue->anjay = anjay;

    if (gpio_add_callback(dev, &glue->push_button_callback)) {
        gpio_pin_interrupt_configure(dev, gpio_pin, GPIO_INT_DISABLE);
        anjay_ipso_button_instance_remove(anjay, iid);
        return -1;
    }
    return 0;
}

int anjay_zephyr_ipso_push_button_object_install(
        anjay_t *anjay,
        struct anjay_zephyr_ipso_button_instance *user_buttons,
        size_t user_buttons_array_length) {
    if (!anjay || !user_buttons || buttons) {
        return -1;
    }

    buttons = (struct button_instance *) avs_calloc(
            user_buttons_array_length, sizeof(struct button_instance));

    if (!buttons) {
        return -1;
    }

    if (anjay_ipso_button_install(anjay, user_buttons_array_length)) {
        return -1;
    }

    for (anjay_iid_t iid = 0; iid < user_buttons_array_length; iid++) {
        buttons[iid].button = &user_buttons[iid];
        configure_push_button(anjay, buttons[iid].button->device,
                              buttons[iid].button->gpio_pin,
                              buttons[iid].button->gpio_flags, iid,
                              &buttons[iid]);
    }

    return 0;
}

void _anjay_zephyr_push_button_clean(void) {
    avs_free(buttons);
    buttons = NULL;
}
