/*
 * device-bitfury.c - device functions for Bitfury chip/board library
 *
 * Copyright (c) 2013 bitfury
 * Copyright (c) 2013 legkodymov
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
*/

#include "miner.h"
#include <unistd.h>
#include <sha2.h>
#include "libbitfury.h"
#include "util.h"
#include "tm_i2cm.h"

#define GOLDEN_BACKLOG 5
#define LINE_LEN 2048

struct device_drv bitfury_drv;
static int voltage_applyed = 2;

// Forward declarations
static void bitfury_disable(struct thr_info* thr);
static bool bitfury_prepare(struct thr_info *thr);
int calc_stat(time_t * stat_ts, time_t stat, struct timeval now);
double shares_to_ghashes(int shares, int seconds);

unsigned char slot_swap(unsigned char slot) {
	unsigned char new_slot = slot;
	switch(slot) {
		case  8 : new_slot = 12; break;
		case  9 : new_slot = 13; break;
		case 12 : new_slot =  8; break;
		case 13 : new_slot =  9; break;
	}
	return new_slot;
}

static void bitfury_detect(void) {
	int chip_n;
	int i;
	struct cgpu_info *bitfury_info;
	static struct bitfury_device *devices;

	bitfury_info = calloc(1, sizeof(struct cgpu_info));
	bitfury_info->drv = &bitfury_drv;
	bitfury_info->threads = 1;

	applog(LOG_INFO, "INFO: bitfury_detect");
	chip_n = libbitfury_detectChips(bitfury_info->devices);
	if (!chip_n) {
		applog(LOG_WARNING, "No Bitfury chips detected!");
		return;
	} else {
		applog(LOG_WARNING, "BITFURY: %d chips detected!", chip_n);
	}

	bitfury_info->chip_n = chip_n;
	add_cgpu(bitfury_info);

	// ### Set all vltage to 0.82V ###
	applog(LOG_INFO, "Set voltage!");
	devices = bitfury_info->devices;
	for(i = 1 ; i < chip_n ; i++) {
		if (devices[i].slot != devices[i - 1].slot || i == 1) {
			unsigned char slot = devices[i].slot;
			applog(LOG_WARNING, "Slot[%02d]: %.3f V\t%.1f C", slot,
				tm_i2c_set_voltage_abs(slot_swap(slot), 0.835), tm_i2c_gettemp(slot_swap(slot)));
		}
	}
}

static uint32_t bitfury_checkNonce(struct work *work, uint32_t nonce)
{
	applog(LOG_INFO, "INFO: bitfury_checkNonce");
}

static int64_t bitfury_scanHash(struct thr_info *thr)
{
	static struct bitfury_device *devices; // TODO Move somewhere to appropriate place
	int chip_n;
	int chip;
	uint64_t hashes = 0;
	struct timeval now;
	unsigned char line[LINE_LEN];
	int short_stat = 10;
	static time_t short_out_t;
	int long_stat = 900;
	static time_t long_out_t;
	int long_long_stat = 60 * 30;
	static time_t long_long_out_t;
	static first = 0; //TODO Move to detect()
	int i;

	devices = thr->cgpu->devices;
	chip_n = thr->cgpu->chip_n;

	if (!first) {
		for (i = 0; i < chip_n; i++) {
			devices[i].osc6_bits = 55;
		}
		for (i = 0; i < chip_n; i++) {
			send_reinit(devices[i].slot, devices[i].fasync, devices[i].osc6_bits);
		}
	}
	first = 1;

	for (chip = 0; chip < chip_n; chip++) {
		devices[chip].job_switched = 0;
		if(!devices[chip].work) {
			devices[chip].work = get_queued(thr->cgpu);
			if (devices[chip].work == NULL) {
				return 0;
			}
			work_to_payload(&(devices[chip].payload), devices[chip].work);
		}
	}

	libbitfury_sendHashData(devices, chip_n);
	nmsleep(5);

	cgtime(&now);
	//chip = 0;
	for (chip = 0 ; chip < chip_n; chip++) {
		if (devices[chip].job_switched) {
			int i,j;
			int *res = devices[chip].results;
			struct work *work = devices[chip].work;
			struct work *owork = devices[chip].owork;
			struct work *o2work = devices[chip].o2work;
			i = devices[chip].results_n;
			for (j = i - 1; j >= 0; j--) {
				if (owork) {
					submit_nonce(thr, owork, bswap_32(res[j]));
					devices[chip].stat_ts[devices[chip].stat_counter++] =
						now.tv_sec;
					if (devices[chip].stat_counter == BITFURY_STAT_N) {
						devices[chip].stat_counter = 0;
					}
				}
				if (o2work) {
					// TEST
					//submit_nonce(thr, owork, bswap_32(res[j]));
				}
			}
			devices[chip].results_n = 0;
			devices[chip].job_switched = 0;
			if (devices[chip].old_nonce && o2work) {
					submit_nonce(thr, o2work, bswap_32(devices[chip].old_nonce));
					i++;
			}
			if (devices[chip].future_nonce) {
					submit_nonce(thr, work, bswap_32(devices[chip].future_nonce));
					i++;
			}

			if (o2work)
				work_completed(thr->cgpu, o2work);

			devices[chip].o2work = devices[chip].owork;
			devices[chip].owork = devices[chip].work;
			devices[chip].work = NULL;
			hashes += 0xffffffffull * i;
		}
	}

	if (now.tv_sec - short_out_t > short_stat) {
		int shares_first = 0, shares_last = 0, shares_total = 0;
		char stat_lines[32][LINE_LEN] = {0};
		int len, k;
		double gh[32][8] = {0};
		double ghsum = 0;
		unsigned strange_counter = 0;

		for (chip = 0; chip < chip_n; chip++) {
			int shares_found = calc_stat(devices[chip].stat_ts, short_stat, now);
			double ghash;
			len = strlen(stat_lines[devices[chip].slot]);
			ghash = shares_to_ghashes(shares_found, short_stat);
			gh[devices[chip].slot][chip & 0x07] = ghash;
			//snprintf(stat_lines[devices[chip].slot] + len, LINE_LEN - len, "%d-%.1f-%3.0f ", devices[chip].osc6_bits, ghash, devices[chip].mhz);
			snprintf(stat_lines[devices[chip].slot] + len, LINE_LEN - len, "%d-%3.0f%c",
				devices[chip].osc6_bits, devices[chip].mhz, (ghash != 0) ? ' ' : '!');
			devices[chip].mhz_stat = (devices[chip].mhz + devices[chip].mhz_stat * 9) / 10;
			if(short_out_t && ghash < 0.5 && devices[chip].osc6_bits > 50) {
				applog(LOG_WARNING, "Chip_id %d FREQ CHANGE", chip);
				send_freq(devices[chip].slot, devices[chip].fasync, 1);
				nmsleep(1);
				send_freq(devices[chip].slot, devices[chip].fasync, devices[chip].osc6_bits);
			}
			shares_total += shares_found;
			shares_first += chip < 4 ? shares_found : 0;
			shares_last += chip > 3 ? shares_found : 0;
			if (devices[chip].strange_counter > short_stat && devices[chip].osc6_bits == 54) devices[chip].osc6_bits -= 4; //!!!
			if (devices[chip].strange_counter > 3 && devices[chip].osc6_bits > 54) devices[chip].osc6_bits--; //!!!
			strange_counter += devices[chip].strange_counter;
			devices[chip].strange_counter = 0;
		}
		applog(LOG_WARNING, "vvvvwww SHORT stat %ds, stranges: %u wwwvvvv", short_stat, strange_counter);
		for(i = 0; i < 32; i++)
			if(strlen(stat_lines[i])) {
				double temp;
				len = strlen(stat_lines[i]);
				ghsum = 0;
				for(k = 0; k < 8; k++) ghsum += gh[i][k];
				temp = tm_i2c_gettemp(slot_swap(i));
				snprintf(stat_lines[i] + len, LINE_LEN - len, "= %2.1f %.1f slot %2d", ghsum, temp, i);
				applog(LOG_WARNING, stat_lines[i]);
				if (temp > 75 && temp < 170) {
					tm_i2c_set_vid(slot_swap(i), 0);
					applog(LOG_WARNING, "-----=====!!!!! Slot %d set low voltage !!!!!=====-----", i);
				}
			}
		short_out_t = now.tv_sec;
	}

	if (now.tv_sec - long_out_t > long_stat) {
		int shares_first = 0, shares_last = 0, shares_total = 0;
		char stat_lines[32][LINE_LEN] = {0};
		int len, k;
		double gh[32][8] = {0};
		double ghsum = 0;
		double mhz_slot[32] = {0}, mhz_count[32] = {0};

		for (chip = 0; chip < chip_n; chip++) {
			int shares_found = calc_stat(devices[chip].stat_ts, long_stat, now);
			double ghash;
			len = strlen(stat_lines[devices[chip].slot]);
			ghash = shares_to_ghashes(shares_found, long_stat);
			gh[devices[chip].slot][chip & 0x07] = ghash;
			snprintf(stat_lines[devices[chip].slot] + len, LINE_LEN - len, "%.1f-%3.0f ", ghash, devices[chip].mhz_stat);
			if (devices[chip].osc6_bits != 50) {
				mhz_slot[devices[chip].slot] += devices[chip].mhz_stat;
				mhz_count[devices[chip].slot]++;
			}
			if (ghash < 2.4) devices[chip].osc6_bits++;
			if (devices[chip].osc6_bits > 57) devices[chip].osc6_bits = 53;
			if (ghash < 1) send_reinit(devices[chip].slot, devices[chip].fasync, devices[chip].osc6_bits); // !!!

			shares_total += shares_found;
			shares_first += chip < 4 ? shares_found : 0;
			shares_last += chip > 3 ? shares_found : 0;
		}
		applog(LOG_WARNING, "!!!_________ LONG stat %ds: ___________!!!", long_stat);
		for(i = 0; i < 32; i++)
			if(strlen(stat_lines[i])) {
				len = strlen(stat_lines[i]);
				ghsum = 0;
				mhz_slot[i] /= mhz_count[i];
				for(k = 0; k < 8; k++) ghsum += gh[i][k];
				snprintf(stat_lines[i] + len, LINE_LEN - len, "= %2.1f-%3.0f slot %2i", ghsum, mhz_slot[i], i);
				applog(LOG_WARNING, stat_lines[i]);
			}
		// ### Set voltage ###
		if (voltage_applyed) {
			applog(LOG_WARNING, "Renew voltage");
			if (voltage_applyed == 1)
				for(i = 0; i < 32; i++) {
					if (!strlen(stat_lines[i])) continue;
					if (mhz_slot[i] < 215) {
						applog(LOG_WARNING, "Slot[%02d] new voltage: %.3f V\t%.1f C",
							i, tm_i2c_set_voltage_abs(slot_swap(i), 0.91), tm_i2c_gettemp(slot_swap(i)));
					} else {
						applog(LOG_WARNING, "Slot[%02d]: no changes", i);
					}
				}
			voltage_applyed--;
		}
		long_out_t = now.tv_sec;
	}

	return hashes;
}

double shares_to_ghashes(int shares, int seconds) {
	return (double)shares / (double)seconds * 4.84387;  //orig: 4.77628
}

int calc_stat(time_t * stat_ts, time_t stat, struct timeval now) {
	int j;
	int shares_found = 0;
	for(j = 0; j < BITFURY_STAT_N; j++) {
		if (now.tv_sec - stat_ts[j] < stat) {
			shares_found++;
		}
	}
	return shares_found;
}

static void bitfury_statline_before(char *buf, struct cgpu_info *cgpu)
{
	applog(LOG_INFO, "INFO bitfury_statline_before");
}

static bool bitfury_prepare(struct thr_info *thr)
{
	struct timeval now;
	struct cgpu_info *cgpu = thr->cgpu;

	cgtime(&now);
	get_datestamp(cgpu->init, &now);

	applog(LOG_INFO, "INFO bitfury_prepare");
	return true;
}

static void bitfury_shutdown(struct thr_info *thr)
{
	int chip_n;
	int i;

	chip_n = thr->cgpu->chip_n;

	applog(LOG_INFO, "INFO bitfury_shutdown");
	libbitfury_shutdownChips(thr->cgpu->devices, chip_n);
}

static void bitfury_disable(struct thr_info *thr)
{
	applog(LOG_INFO, "INFO bitfury_disable");
}

struct device_drv bitfury_drv = {
	.drv_id = DRIVER_BITFURY,
	.dname = "bitfury",
	.name = "BITFURY",
	.drv_detect = bitfury_detect,
	.get_statline_before = bitfury_statline_before,
	.thread_prepare = bitfury_prepare,
	.scanwork = bitfury_scanHash,
	.thread_shutdown = bitfury_shutdown,
	.hash_work = hash_queued_work,
};

