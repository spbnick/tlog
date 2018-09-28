/*
 * Functions handling struct timespec.
 *
 * Copyright (C) 2015 Red Hat
 *
 * This file is part of tlog.
 *
 * Tlog is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tlog is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with tlog; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#define _XOPEN_SOURCE 500
#define _GNU_SOURCE
#include <tlog/timespec.h>
#include <time.h>
#include <string.h>

/* NOTE: Not using the macro from the header to workaround a gcc 4.8 bug */
const struct timespec tlog_timespec_zero = {0, 0};

const struct timespec tlog_timespec_min = {LONG_MIN, -TLOG_TIMESPEC_NSEC_PER_SEC + 1};

const struct timespec tlog_timespec_max = {LONG_MAX, TLOG_TIMESPEC_NSEC_PER_SEC - 1};

#define TLOG_TIMESPEC_FP_OP_ADD +
#define TLOG_TIMESPEC_FP_OP_SUB -
#define TLOG_TIMESPEC_FP_OP_MUL *
#define TLOG_TIMESPEC_FP_OP_DIV /

#define TLOG_TIMESPEC_FP_CALC(_a, _op, _b, _res) \
    do {                                            \
        double _ts;                                 \
                                                    \
        _ts = tlog_timespec_to_fp(a)                \
              TLOG_TIMESPEC_FP_OP_##_op             \
              tlog_timespec_to_fp(b);               \
        _ts = tlog_timespec_fp_cap(_ts);            \
        tlog_timespec_from_fp(_ts, _res);           \
    } while (0)

void
tlog_timespec_add(const struct timespec *a,
                  const struct timespec *b,
                  struct timespec *res)
{
    struct timespec tmp;

    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);

    tmp.tv_sec = a->tv_sec + b->tv_sec;
    tmp.tv_nsec = a->tv_nsec + b->tv_nsec;

    /* Carry from nsec */
    if (b->tv_sec >= 0 && b->tv_nsec >= 0) {
        if (tmp.tv_sec >= 0 ? tmp.tv_nsec >= TLOG_TIMESPEC_NSEC_PER_SEC
                            : tmp.tv_nsec > 0) {
            tmp.tv_sec++;
            tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    } else {
        if (tmp.tv_sec > 0 ? tmp.tv_nsec < 0
                           : tmp.tv_nsec <= -TLOG_TIMESPEC_NSEC_PER_SEC) {
            tmp.tv_sec--;
            tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    }

    /* Carry from sec */
    if (tmp.tv_sec < 0 && tmp.tv_nsec > 0) {
        tmp.tv_sec++;
        tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
    } else if (tmp.tv_sec > 0 && tmp.tv_nsec < 0) {
        tmp.tv_sec--;
        tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
    }

    *res = tmp;
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_sub(const struct timespec *a,
                  const struct timespec *b,
                  struct timespec *res)
{
    struct timespec tmp;

    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);

    tmp.tv_sec = a->tv_sec - b->tv_sec;
    tmp.tv_nsec = a->tv_nsec - b->tv_nsec;

    /* Carry from nsec */
    if (b->tv_sec < 0 || b->tv_nsec < 0) {
        if (tmp.tv_sec >= 0 ? tmp.tv_nsec >= TLOG_TIMESPEC_NSEC_PER_SEC
                            : tmp.tv_nsec > 0) {
            tmp.tv_sec++;
            tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    } else {
        if (tmp.tv_sec > 0 ? tmp.tv_nsec < 0
                           : tmp.tv_nsec <= -TLOG_TIMESPEC_NSEC_PER_SEC) {
            tmp.tv_sec--;
            tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    }

    /* Carry from sec */
    if (tmp.tv_sec < 0 && tmp.tv_nsec > 0) {
        tmp.tv_sec++;
        tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
    } else if (tmp.tv_sec > 0 && tmp.tv_nsec < 0) {
        tmp.tv_sec--;
        tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
    }

    *res = tmp;
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_cap_add(const struct timespec *a,
                      const struct timespec *b,
                      struct timespec *res)
{
    struct timespec tmp;

    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);

    tmp.tv_sec = a->tv_sec + b->tv_sec;

    /* If overflow */
    if ((a->tv_sec >= 0) == (b->tv_sec >= 0) &&
        (a->tv_sec >= 0) != (tmp.tv_sec >= 0)) {
        *res = (tmp.tv_sec >= 0) ? tlog_timespec_min : tlog_timespec_max;
        goto exit;
    }

    tmp.tv_nsec = a->tv_nsec + b->tv_nsec;

    /* Carry from nsec */
    if (b->tv_sec >= 0 && b->tv_nsec >= 0) {
        if (tmp.tv_sec >= 0 ? tmp.tv_nsec >= TLOG_TIMESPEC_NSEC_PER_SEC
                            : tmp.tv_nsec > 0) {
            /* If overflow */
            if (tmp.tv_sec == LONG_MAX) {
                *res = tlog_timespec_max;
                goto exit;
            }
            tmp.tv_sec++;
            tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    } else {
        if (tmp.tv_sec > 0 ? tmp.tv_nsec < 0
                           : tmp.tv_nsec <= -TLOG_TIMESPEC_NSEC_PER_SEC) {
            /* If overflow */
            if (tmp.tv_sec == LONG_MIN) {
                *res = tlog_timespec_min;
                goto exit;
            }
            tmp.tv_sec--;
            tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    }

    /* Carry from sec */
    if (tmp.tv_sec < 0 && tmp.tv_nsec > 0) {
        tmp.tv_sec++;
        tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
    } else if (tmp.tv_sec > 0 && tmp.tv_nsec < 0) {
        tmp.tv_sec--;
        tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
    }

    *res = tmp;
exit:
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_cap_sub(const struct timespec *a,
                      const struct timespec *b,
                      struct timespec *res)
{
    struct timespec tmp;

    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);

    tmp.tv_sec = a->tv_sec - b->tv_sec;

    /* If overflow */
    if ((a->tv_sec >= 0) != (b->tv_sec >= 0) &&
        (a->tv_sec >= 0) != (tmp.tv_sec >= 0)) {
        *res = (tmp.tv_sec >= 0) ? tlog_timespec_min : tlog_timespec_max;
        goto exit;
    }

    tmp.tv_nsec = a->tv_nsec - b->tv_nsec;

    /* Carry from nsec */
    if (b->tv_sec < 0 || b->tv_nsec < 0) {
        if (tmp.tv_sec >= 0 ? tmp.tv_nsec >= TLOG_TIMESPEC_NSEC_PER_SEC
                            : tmp.tv_nsec > 0) {
            /* If overflow */
            if (tmp.tv_sec == LONG_MAX) {
                *res = tlog_timespec_max;
                goto exit;
            }
            tmp.tv_sec++;
            tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    } else {
        if (tmp.tv_sec > 0 ? tmp.tv_nsec < 0
                           : tmp.tv_nsec <= -TLOG_TIMESPEC_NSEC_PER_SEC) {
            /* If overflow */
            if (tmp.tv_sec == LONG_MIN) {
                *res = tlog_timespec_min;
                goto exit;
            }
            tmp.tv_sec--;
            tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
        }
    }

    /* Carry from sec */
    if (tmp.tv_sec < 0 && tmp.tv_nsec > 0) {
        tmp.tv_sec++;
        tmp.tv_nsec -= TLOG_TIMESPEC_NSEC_PER_SEC;
    } else if (tmp.tv_sec > 0 && tmp.tv_nsec < 0) {
        tmp.tv_sec--;
        tmp.tv_nsec += TLOG_TIMESPEC_NSEC_PER_SEC;
    }

    *res = tmp;
exit:
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_fp_add(const struct timespec *a,
                     const struct timespec *b,
                     struct timespec *res)
{
    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);
    TLOG_TIMESPEC_FP_CALC(a, ADD, b, res);
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_fp_sub(const struct timespec *a,
                     const struct timespec *b,
                     struct timespec *res)
{
    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);
    TLOG_TIMESPEC_FP_CALC(a, SUB, b, res);
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_fp_mul(const struct timespec *a,
                     const struct timespec *b,
                     struct timespec *res)
{
    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);
    TLOG_TIMESPEC_FP_CALC(a, MUL, b, res);
    assert(tlog_timespec_is_valid(res));
}

void
tlog_timespec_fp_div(const struct timespec *a,
                     const struct timespec *b,
                     struct timespec *res)
{
    assert(tlog_timespec_is_valid(a));
    assert(tlog_timespec_is_valid(b));
    assert(res != NULL);
    TLOG_TIMESPEC_FP_CALC(a, DIV, b, res);
    assert(tlog_timespec_is_valid(res));
}

tlog_grc
tlog_timespec_from_rfc3339(const char *str,
                           struct timespec *res)
{
    tlog_grc grc = TLOG_RC_TIMESPEC_RFC3339_INVALID;
    /* NOTE: Relying on strptime not modifying struct tm unnecessarily */
    struct tm tm = {0,};
    int n;
    int rc;
    time_t sec;
    long int nsec;
    char *orig_tz = NULL;
    char tz_buf[48];

    assert(str != NULL);

    /* Parse date */
    str = strptime(str, "%F", &tm);
    if (str == NULL) {
        goto cleanup;
    }

    /* Check for date/time separator */
    if (*str == ' ' || *str == 'T' || *str == 't') {
        str++;
    } else {
        goto cleanup;
    }

    /* Parse time down to whole seconds */
    str = strptime(str, "%T", &tm);
    if (str == NULL) {
        goto cleanup;
    }

    /* If there are fractions of a second following */
    if (*str == '.' || *str == ',') {
        str++;
        /* Detect whitespace */
        (void)sscanf(str, " %n", &n);
        if (n > 0) {
            goto cleanup;
        }
        /* Parse fractions */
        rc = sscanf(str, "%ld%n", &nsec, &n);
        if (rc != 1 || nsec < 0) {
            goto cleanup;
        }
        str += n;
        /* Convert to nanoseconds */
        for (; n < 9; n++) {
            nsec *= 10;
        }
        for (; n > 9; n--) {
            nsec /= 10;
        }
    } else {
        nsec = 0;
    }

    /* Detect whitespace */
    (void)sscanf(str, " %n", &n);
    if (n > 0) {
        goto cleanup;
    }

    /* Parse timezone */
    str = strptime(str, "%z", &tm);
    if (str == NULL) {
        goto cleanup;
    }

    /* Consume trailing whitespace */
    (void)sscanf(str, " %n", &n);
    str += n;
    if (*str != '\0') {
        goto cleanup;
    }

    /* Save current TZ environment variable */
    orig_tz = getenv("TZ");
    if (orig_tz != NULL) {
        orig_tz = strdup(orig_tz);
        if (orig_tz == NULL) {
            grc = TLOG_GRC_ERRNO;
            goto cleanup;
        }
    }

    /*
     * Format parsed timezone as a TZ value. Sorry, there doesn't seem to be
     * another way to communicate the timezone.
     */
    {
        long int tz_gmtoff;
        char tz_sign;
        long int tz_hours;
        long int tz_minutes;
        long int tz_seconds;

        tz_gmtoff = tm.tm_gmtoff;
        if (tz_gmtoff <= 0) {
            tz_sign = '+';
            tz_gmtoff = -tz_gmtoff;
        } else {
            tz_sign = '-';
        }
        tz_seconds = tz_gmtoff % 60;
        tz_gmtoff /= 60;
        tz_minutes = tz_gmtoff % 60;
        tz_hours = tz_gmtoff / 60;
        if (snprintf(tz_buf, sizeof(tz_buf), "CUSTOM%c%02ld:%02ld:%02ld",
                     tz_sign, tz_hours, tz_minutes, tz_seconds) >=
                (int)sizeof(tz_buf)) {
            grc = TLOG_GRC_FROM(errno, ENOMEM);
            goto cleanup;
        }
    }

    /* Set TZ environment variable temporarily */
    if (setenv("TZ", tz_buf, 1 /* overwrite */) < 0) {
        grc = TLOG_GRC_ERRNO;
        goto cleanup;
    }

    /* Convert to seconds since epoch, using the specified timezone */
    errno = 0;
    sec = mktime(&tm);
    if (sec < 0) {
        grc = (errno == 0) ? TLOG_RC_FAILURE : TLOG_GRC_ERRNO;
        goto cleanup;
    }

    /* Restore the original TZ environment variable */
    if (orig_tz == NULL) {
        if (unsetenv("TZ") < 0) {
            grc = TLOG_GRC_ERRNO;
            goto cleanup;
        }
    } else {
        if (setenv("TZ", orig_tz, 1 /* overwrite */) < 0) {
            grc = TLOG_GRC_ERRNO;
            goto cleanup;
        }
        free(orig_tz);
        orig_tz = NULL;
    }

    /* Output the result, if requested */
    if (res != NULL) {
        res->tv_sec = sec;
        res->tv_nsec = nsec;
        assert(tlog_timespec_is_valid(res));
    }

    grc = TLOG_RC_OK;

cleanup:
    free(orig_tz);
    return grc;
}

tlog_grc
tlog_timespec_to_rfc3339(char *buf, size_t len, const struct timespec *ts)
{
    struct tm tm;
    size_t written;
    char zone_buf[16];
    int rc;

    assert(buf != NULL || len == 0);
    assert(tlog_timespec_is_valid(ts));
    assert(tlog_timespec_is_zero(ts) || tlog_timespec_is_positive(ts));

    /* Convert to local time */
    errno = 0;
    if (localtime_r(&ts->tv_sec, &tm) == NULL) {
        return (errno == 0) ? TLOG_RC_FAILURE : TLOG_GRC_ERRNO;
    }

    /* Output date and time */
    written = strftime(buf, len, "%FT%T", &tm);
    if (written == 0) {
        return TLOG_RC_TIMESPEC_RFC3339_NOSPACE;
    }
    buf += written;
    len -= written;

    /* Output fractions of second, if any */
    if (ts->tv_nsec != 0) {
        errno = 0;
        rc = snprintf(buf, len, ".%09ld", ts->tv_nsec);
        if (rc < 0) {
            return (errno == 0) ? TLOG_RC_FAILURE : TLOG_GRC_ERRNO;
        } else if ((size_t)rc >= len) {
            return TLOG_RC_TIMESPEC_RFC3339_NOSPACE;
        }
        buf += rc;
        len -= rc;
    }

    /* Output timezone offset */
    written = strftime(zone_buf, sizeof(zone_buf), "%z", &tm);
    if (written == 0) {
        return TLOG_GRC_FROM(errno, ENOMEM);
    }
    if (written < 5) {
        return TLOG_RC_FAILURE;
    }
    errno = 0;
    rc = snprintf(buf, len, "%.3s:%s", zone_buf, zone_buf + 3);
    if (rc < 0) {
        return (errno == 0) ? TLOG_RC_FAILURE : TLOG_GRC_ERRNO;
    } else if ((size_t)rc >= len) {
        return TLOG_RC_TIMESPEC_RFC3339_NOSPACE;
    }

    return TLOG_RC_OK;
}
