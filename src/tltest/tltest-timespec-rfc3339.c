/*
 * Tlog timespec module test.
 *
 * Copyright (C) 2017 Red Hat
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

#include <tlog/timespec.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

static bool
test_from_init(const char *file, int line,
               const char *tz,
               const char *str,
               tlog_grc exp_grc,
               const struct timespec *valid_res,
               const struct timespec *init_res)
{
    int rc;
    const char *tz_after;
    tlog_grc grc;
    const struct timespec *exp_res = (exp_grc == TLOG_RC_OK)
                                        ? valid_res
                                        : init_res;
    struct timespec res = *init_res;
    bool passed;

    assert(file != NULL);
    assert(str != NULL);
    assert(exp_grc != TLOG_RC_OK || tlog_timespec_is_valid(valid_res));
    assert(tlog_timespec_is_valid(init_res));

    if (tz == NULL) {
        rc = unsetenv("TZ");
        assert(rc == 0);
    } else {
        rc = setenv("TZ", tz, 1 /* overwrite */);
        assert(rc == 0);
    }

    grc = tlog_timespec_from_rfc3339(str, &res);

    tz_after = getenv("TZ");

    passed = ((tz == NULL) == (tz_after == NULL)) &&
             (tz == NULL || strcmp(tz, tz_after) == 0) &&
             (grc == exp_grc) &&
             (res.tv_sec == exp_res->tv_sec) &&
             (res.tv_nsec == exp_res->tv_nsec);

#define STR_OR_NULL_ARG(_str_or_null) \
    ((_str_or_null) == NULL ? "" : "\""),               \
    ((_str_or_null) == NULL ? "NULL" : (_str_or_null)), \
    ((_str_or_null) == NULL ? "" : "\"")

    fprintf(stderr,
            "%s %s:%d "
            "tlog_timespec_from_rfc3339(%s%s%s, \"%s\", " TLOG_TIMESPEC_FMT ")"
            " => "
            "(%s%s%s, \"%s\", " TLOG_TIMESPEC_FMT ")"
            " %s "
            "(%s%s%s, \"%s\", " TLOG_TIMESPEC_FMT ")"
            "\n",
            (passed ? "PASS" : "FAIL"), file, line,
            STR_OR_NULL_ARG(tz),
            str, TLOG_TIMESPEC_ARG(init_res),
            STR_OR_NULL_ARG(tz_after),
            tlog_grc_strerror(grc), TLOG_TIMESPEC_ARG(&res),
            (passed ? "==": "!="),
            STR_OR_NULL_ARG(tz),
            tlog_grc_strerror(exp_grc), TLOG_TIMESPEC_ARG(exp_res));

#undef STR_OR_NULL_ARG

    return passed;
}

/**
 * Test if tlog_timespec_from_rfc3339 function returns expected values with
 * various initial "TZ" environment variable values and contents of the output
 * variable.
 *
 * @param file      The filename of the test invocation.
 * @param line      The line number of the test invocation.
 * @param str       The string to attempt to parse with
 *                  tlog_timespec_from_rfc3339.
 * @param exp_grc   The global return code the tlog_timespec_from_rfc3339 is
 *                  expected to return.
 * @param valid_res A pointer to a struct timespec containing the value
 *                  tlog_timespec_from_rfc3339 is expected to return as parsed
 *                  out of str, if succeeded. Can only be NULL if "grc" is not
 *                  TLOG_RC_OK.
 *
 * @return True if all tests have passed, false if not.
 */
static bool
test_from(const char *file, int line,
          const char *str, tlog_grc exp_grc, const struct timespec *valid_res)
{
    bool passed = true;
    const char *tz_list[] = {NULL, "", "GMT"};
    size_t i;
    struct timespec init_res0 = {0, 0};
    struct timespec init_res1 = {0, 0};

    assert(file != NULL);
    assert(str != NULL);
    assert(exp_grc != TLOG_RC_OK || valid_res != NULL);

    init_res1.tv_sec = ~init_res1.tv_sec;
    init_res1.tv_nsec = ~init_res1.tv_nsec;

    for (i = 0; i < TLOG_ARRAY_SIZE(tz_list); i++) {
        passed = test_from_init(file, line, tz_list[i],
                                str, exp_grc, valid_res, &init_res0) &&
                 passed;
        passed = test_from_init(file, line, tz_list[i],
                                str, exp_grc, valid_res, &init_res1) &&
                 passed;
    }
    return passed;
}

/**
 * Test if tlog_timespec_to_rfc3339 function returns expected values for
 * specified timespec.
 *
 * @param file      The filename of the test invocation.
 * @param line      The line number of the test invocation.
 * @param tz        Value to set the "TZ" environment variable to, before
 *                  executing tlog_timespec_to_rfc3339.
 * @param len       The length of the output buffer to supply to
 *                  tlog_timespec_to_rfc3339.
 * @param ts        The timespec to convert to RFC 3339 string with
 *                  tlog_timespec_to_rfc3339.
 * @param exp_grc   The global return code the tlog_timespec_to_rfc3339 is
 *                  expected to return.
 * @param exp_str   The formatted RFC 3339 string the tlog_timespec_to_rfc3339
 *                  is supposed to output. Only used if exp_grc is TLOG_RC_OK.
 *
 * @return True if all tests have passed, false if not.
 */
static bool
test_to(const char *file, int line,
        const char *tz,
        size_t len, const struct timespec *ts,
        tlog_grc exp_grc, const char *exp_str)
{
    char *buf;
    int setenv_rc;
    tlog_grc grc;
    bool passed;

    assert(file != NULL);
    assert(tz != NULL);
    assert(ts != NULL);
    assert(exp_grc != TLOG_RC_OK || exp_str != NULL);

    buf = malloc(len);
    assert(buf != NULL);
    setenv_rc = setenv("TZ", tz, 1 /* overwrite */);
    assert(setenv_rc == 0);
    tzset();
    grc = tlog_timespec_to_rfc3339(buf, len, ts);

    if (grc != TLOG_RC_OK) {
        buf[0] = '\0';
    }
    if (exp_grc != TLOG_RC_OK) {
        exp_str = "";
    }

    passed = (grc == exp_grc) &&
             strcmp(buf, exp_str) == 0;

    fprintf(stderr,
            "%s %s:%d "
            "tlog_timespec_to_rfc3339(\"%s\", %zu, " TLOG_TIMESPEC_FMT ")"
            " => "
            "(\"%s\", \"%s\")"
            " %s "
            "(\"%s\", \"%s\")"
            "\n",
            (passed ? "PASS" : "FAIL"), file, line,
            tz, len, TLOG_TIMESPEC_ARG(ts),
            tlog_grc_strerror(grc), buf,
            (passed ? "==": "!="),
            tlog_grc_strerror(exp_grc), exp_str);

    free(buf);
    return passed;
}

/**
 * Test that a timespec is unchanged after passing through
 * tlog_timespec_to_rfc3339 and tlog_timespec_from_rfc3339, for specified
 * timezone string.
 *
 * @param file      The filename of the test invocation.
 * @param line      The line number of the test invocation.
 * @param tz        Value to set the "TZ" environment variable to, before
 *                  executing tlog_timespec_to_rfc3339.
 * @param ts        The timespec to pass through the functions.
 *
 * @return True if all tests have passed, false if not.
 */
static bool
test_through_ts(const char *file, int line,
                 const char *tz, const struct timespec *ts)
{
    bool passed;
    int setenv_rc;
    tlog_grc to_grc;
    tlog_grc from_grc;
    char buf[64];
    struct timespec init_ts = {0, 0};
    struct timespec res_ts = init_ts;

    assert(file != NULL);
    assert(tz != NULL);
    assert(ts != NULL);

    setenv_rc = setenv("TZ", tz, 1 /* overwrite */);
    assert(setenv_rc == 0);
    tzset();

    to_grc = tlog_timespec_to_rfc3339(buf, sizeof(buf), ts);
    if (to_grc == TLOG_RC_OK) {
        from_grc = tlog_timespec_from_rfc3339(buf, &res_ts);
    }

    passed = (to_grc == TLOG_RC_OK) &&
             (from_grc == TLOG_RC_OK) &&
             (res_ts.tv_sec == ts->tv_sec) &&
             (res_ts.tv_nsec == ts->tv_nsec);

    fprintf(stderr,
            "%s %s:%d "
            "tlog_timespec_to_rfc3339(\"%s\", " TLOG_TIMESPEC_FMT ")"
            " => "
            "(\"%s\" %s \"%s\", \"%s\")",
            (passed ? "PASS" : "FAIL"), file, line,
            tz, TLOG_TIMESPEC_ARG(ts),
            tlog_grc_strerror(to_grc),
            (to_grc == TLOG_RC_OK ? "==" : "!="),
            tlog_grc_strerror(TLOG_RC_OK),
            buf);

    if (to_grc == TLOG_RC_OK) {
        fprintf(stderr,
                ", "
                "tlog_timespec_from_rfc3339(\"%s\", " TLOG_TIMESPEC_FMT ")"
                " => "
                "(\"%s\", " TLOG_TIMESPEC_FMT ")"
                " %s "
                "(\"%s\", " TLOG_TIMESPEC_FMT ")",
                buf, TLOG_TIMESPEC_ARG(&init_ts),
                tlog_grc_strerror(from_grc), TLOG_TIMESPEC_ARG(&res_ts),
                (passed ? "==": "!="),
                tlog_grc_strerror(TLOG_RC_OK), TLOG_TIMESPEC_ARG(ts));
    }

    fprintf(stderr, "\n");

    return passed;
}

/**
 * Test that an RFC 3339 string is unchanged after passing through
 * tlog_timespec_from_rfc3339 and tlog_timespec_to_rfc3339, for specified
 * timezone string.
 *
 * @param file      The filename of the test invocation.
 * @param line      The line number of the test invocation.
 * @param tz        Value to set the "TZ" environment variable to, before
 *                  executing tlog_timespec_to_rfc3339.
 * @param str       The string to pass through the functions.
 *
 * @return True if all tests have passed, false if not.
 */
static bool
test_through_str(const char *file, int line,
                 const char *tz, const char *str)
{
    bool passed;
    int setenv_rc;
    tlog_grc from_grc;
    tlog_grc to_grc;
    char buf[64];
    struct timespec init_ts = {0, 0};
    struct timespec res_ts = init_ts;

    assert(file != NULL);
    assert(tz != NULL);
    assert(str != NULL);

    from_grc = tlog_timespec_from_rfc3339(str, &res_ts);
    if (from_grc == TLOG_RC_OK) {
        setenv_rc = setenv("TZ", tz, 1 /* overwrite */);
        assert(setenv_rc == 0);
        tzset();
        to_grc = tlog_timespec_to_rfc3339(buf, sizeof(buf), &res_ts);
    }

    passed = (to_grc == TLOG_RC_OK) &&
             (from_grc == TLOG_RC_OK) &&
             (strcmp(str, buf) == 0);

    fprintf(stderr,
            "%s %s:%d "
            "tlog_timespec_from_rfc3339(\"%s\", " TLOG_TIMESPEC_FMT ")"
            " => "
            "(\"%s\" %s \"%s\", " TLOG_TIMESPEC_FMT ")",
            (passed ? "PASS" : "FAIL"), file, line,
            str, TLOG_TIMESPEC_ARG(&init_ts),
            tlog_grc_strerror(from_grc),
            (from_grc == TLOG_RC_OK ? "==" : "!="),
            tlog_grc_strerror(TLOG_RC_OK),
            TLOG_TIMESPEC_ARG(&res_ts));

    if (from_grc == TLOG_RC_OK) {
        fprintf(stderr,
                ", "
                "tlog_timespec_to_rfc3339(\"%s\", " TLOG_TIMESPEC_FMT ")"
                " => "
                "(\"%s\", \"%s\")"
                " %s "
                "(\"%s\", \"%s\")",
                tz, TLOG_TIMESPEC_ARG(&res_ts),
                tlog_grc_strerror(to_grc), buf,
                (passed ? "==": "!="),
                tlog_grc_strerror(TLOG_RC_OK), str);
    }

    fprintf(stderr, "\n");

    return passed;
}

int
main(void)
{
    bool passed = true;

#define TS(_sec, _nsec) (struct timespec){_sec, _nsec}

#define TEST_FROM_INVALID(_str) \
    do {                                                                    \
        passed = test_from(__FILE__, __LINE__,                              \
                           _str, TLOG_RC_TIMESPEC_RFC3339_INVALID, NULL) && \
                    passed;                                                 \
    } while (0)

#define TEST_FROM_OK(_str, _exp_res) \
    do {                                                    \
        struct timespec exp_res = _exp_res;                 \
        passed = test_from(__FILE__, __LINE__,              \
                           _str, TLOG_RC_OK, &exp_res) &&   \
                    passed;                                 \
    } while (0)

#define TEST_TO_NOSPACE(_tz, _len, _ts) \
    do {                                                            \
        struct timespec ts = _ts;                                   \
        passed = test_to(__FILE__, __LINE__, _tz, _len, &ts,        \
                         TLOG_RC_TIMESPEC_RFC3339_NOSPACE, NULL) && \
                    passed;                                         \
    } while (0)

#define TEST_TO_OK(_tz, _ts, _exp_str) \
    do {                                                \
        struct timespec ts = _ts;                       \
        passed = test_to(__FILE__, __LINE__, _tz, 64,   \
                         &ts, TLOG_RC_OK, _exp_str) &&  \
                    passed;                             \
    } while (0)

#define TEST_THROUGH_TS(_tz, _ts) \
    do {                                                                    \
        struct timespec ts = _ts;                                           \
        passed = test_through_ts(__FILE__, __LINE__, _tz, &ts) && passed;  \
    } while (0)

#define TEST_THROUGH_STR(_tz, _str) \
    do {                                                                    \
        passed = test_through_str(__FILE__, __LINE__, _tz, _str) && passed; \
    } while (0)

    TEST_FROM_INVALID("");
    TEST_FROM_INVALID(" ");

    TEST_FROM_INVALID("2018-10-03");
    TEST_FROM_INVALID("2018-10-03 13:59:10");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528");

    TEST_FROM_INVALID("201810-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 1359:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.57978052803:00");

    TEST_FROM_INVALID("X2018-10-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID(" X2018-10-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID("X 2018-10-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID(" X 2018-10-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03:00X");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03:00X ");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03:00 X");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03:00 X ");
    TEST_FROM_INVALID("2018-10-03X13:59:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 X 13:59:10.579780528+03:00");

    TEST_FROM_INVALID("2018 -10-03 13:59:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13 :59:10.579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10 .579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10. 579780528+03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528 +03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+ 03:00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03 :00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03: 00");
    TEST_FROM_INVALID("2018-10-03 13:59:10.579780528+03 00");

    TEST_FROM_OK(" 2018-10-03 13:59:10.579780528+03:00",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03 13:59:10.579780528+03:00 ",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03  13:59:10.579780528+03:00",
                 TS(1538564350, 579780528));

    TEST_FROM_OK("2018-10-03 13:59:10,579780528+03:00",
                 TS(1538564350, 579780528));

    TEST_FROM_OK("2018-10-03 13:59:10.579780528+0300",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03 13:59:10.579780528+03:00",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03 07:59:10.579780528-03:00",
                 TS(1538564350, 579780528));

    TEST_FROM_OK("2018-10-03 10:59:10.579780528+00:00",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03 10:59:10.579780528-00:00",
                 TS(1538564350, 579780528));

    TEST_FROM_OK("2018-10-03T13:59:10,579780528+03:00",
                 TS(1538564350, 579780528));
    TEST_FROM_OK("2018-10-03t13:59:10,579780528+03:00",
                 TS(1538564350, 579780528));

    TEST_FROM_OK("1970-01-01 00:00:00.000000000+00:00",
                 TS(0, 0));
    TEST_FROM_OK("2038-01-19 03:14:07.999999999+00:00",
                 TS(INT_MAX, 999999999));

    TEST_TO_NOSPACE("", 0, TS(0, 0));
    TEST_TO_NOSPACE("", 1, TS(0, 0));
    TEST_TO_NOSPACE("", 5, TS(0, 0));
    TEST_TO_NOSPACE("", 11, TS(0, 0));
    TEST_TO_NOSPACE("", 12, TS(0, 0));
    TEST_TO_NOSPACE("", 20, TS(0, 0));
    TEST_TO_NOSPACE("", 20, TS(0, 999999999));
    TEST_TO_NOSPACE("", 25, TS(0, 0));
    TEST_TO_NOSPACE("", 35, TS(0, 999999999));

    TEST_TO_OK("", TS(0, 0),
               "1970-01-01T00:00:00+00:00");
    TEST_TO_OK("", TS(0, 999999999),
               "1970-01-01T00:00:00.999999999+00:00");
    TEST_TO_OK("GMT", TS(0, 0),
               "1970-01-01T00:00:00+00:00");
    TEST_TO_OK("Europe/Prague", TS(0, 0),
               "1970-01-01T01:00:00+01:00");
    TEST_TO_OK("Europe/Helsinki", TS(0, 0),
               "1970-01-01T02:00:00+02:00");
    TEST_TO_OK("CUSTOM-03:00:00", TS(1538564350, 579780528),
               "2018-10-03T13:59:10.579780528+03:00");
    TEST_TO_OK("CUSTOM-24:59:00", TS(1538564350, 579780528),
               "2018-10-04T11:58:10.579780528+24:59");
    TEST_TO_OK("CUSTOM+24:59:00", TS(1538564350, 579780528),
               "2018-10-02T10:00:10.579780528-24:59");
    TEST_TO_OK("", TS(32503680000, 0),
               "3000-01-01T00:00:00+00:00");
    TEST_TO_OK("CUSTOM-24:59:00", TS(32503680000, 0),
               "3000-01-02T00:59:00+24:59");
    TEST_TO_OK("CUSTOM+24:59:00", TS(32503680000, 0),
               "2999-12-30T23:01:00-24:59");

    TEST_THROUGH_TS("", TS(0, 0));
    TEST_THROUGH_TS("CUSTOM+24:59:00", TS(0, 0));
    TEST_THROUGH_TS("CUSTOM-24:59:00", TS(0, 0));

    TEST_THROUGH_TS("", TS(0, 999999999));
    TEST_THROUGH_TS("CUSTOM+24:59:00", TS(0, 999999999));
    TEST_THROUGH_TS("CUSTOM-24:59:00", TS(0, 999999999));

    TEST_THROUGH_TS("", TS(INT_MAX, 999999999));
    TEST_THROUGH_TS("CUSTOM+24:59:00", TS(INT_MAX, 999999999));
    TEST_THROUGH_TS("CUSTOM-24:59:00", TS(INT_MAX, 999999999));

    TEST_THROUGH_TS("", TS(32503680000, 0));
    TEST_THROUGH_TS("CUSTOM+24:59:00", TS(32503680000, 0));
    TEST_THROUGH_TS("CUSTOM-24:59:00", TS(32503680000, 0));

    TEST_THROUGH_STR("", "1970-01-01T00:00:00+00:00");
    TEST_THROUGH_STR("CUSTOM+24:59:00", "1969-12-30T23:01:00-24:59");
    TEST_THROUGH_STR("CUSTOM-24:59:00", "1970-01-02T00:59:00+24:59");

    TEST_THROUGH_STR("", "1970-01-01T00:00:00.900000000+00:00");
    TEST_THROUGH_STR("CUSTOM+24:59:00", "1969-12-30T23:01:00.900000000-24:59");
    TEST_THROUGH_STR("CUSTOM-24:59:00", "1970-01-02T00:59:00.900000000+24:59");

    TEST_THROUGH_STR("", "1970-01-01T00:00:00.999999999+00:00");
    TEST_THROUGH_STR("CUSTOM+24:59:00", "1969-12-30T23:01:00.999999999-24:59");
    TEST_THROUGH_STR("CUSTOM-24:59:00", "1970-01-02T00:59:00.999999999+24:59");

    TEST_THROUGH_STR("", "3000-01-01T00:00:00+00:00");
    TEST_THROUGH_STR("CUSTOM-24:59:00", "3000-01-02T00:59:00+24:59");
    TEST_THROUGH_STR("CUSTOM+24:59:00", "2999-12-30T23:01:00-24:59");

    return !passed;
}
