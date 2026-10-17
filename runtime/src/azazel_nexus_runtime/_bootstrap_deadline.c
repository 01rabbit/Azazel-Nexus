#define _POSIX_C_SOURCE 200809L
#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#if !defined(__linux__) || !defined(CLOCK_BOOTTIME)
#error "The bootstrap deadline requires native Linux CLOCK_BOOTTIME"
#endif

#define CAPSULE "azazel_nexus_runtime.boottime_self_deadline"
#define NS_PER_SECOND 1000000000LL

typedef struct {
    timer_t timer;
    pid_t owner;
    long long deadline;
    int released;
} Deadline;

/* Process-local, nonrenewable. No exported function resets this flag. */
static int consumed = 0;

static void forget_handle(PyObject *capsule) {
    Deadline *value = PyCapsule_GetPointer(capsule, CAPSULE);
    if (value != NULL) {
        /* Intentionally do NOT cancel an armed timer on GC or context exit.
         * SIGEV_SIGNAL has no pointer into this allocation. The kernel retains
         * the timer until explicit release, expiry, process exit or exec. */
        free(value);
    } else {
        PyErr_Clear();
    }
}

static Deadline *owned_handle(PyObject *capsule) {
    Deadline *value = PyCapsule_GetPointer(capsule, CAPSULE);
    if (value == NULL) return NULL;
    if (value->owner != getpid()) {
        PyErr_SetString(PyExc_RuntimeError, "deadline belongs to another process");
        return NULL;
    }
    return value;
}

static int boottime_ns(long long *result) {
    struct timespec now;
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
        PyErr_SetFromErrno(PyExc_OSError);
        return -1;
    }
    if (now.tv_sec < 0 || now.tv_nsec < 0 || now.tv_nsec >= NS_PER_SECOND ||
        (uint64_t)now.tv_sec > (uint64_t)(INT64_MAX / NS_PER_SECOND) ||
        (uint64_t)now.tv_sec * NS_PER_SECOND + now.tv_nsec > INT64_MAX) {
        PyErr_SetString(PyExc_OverflowError, "boottime is outside deadline range");
        return -1;
    }
    *result = (long long)now.tv_sec * NS_PER_SECOND + now.tv_nsec;
    return 0;
}

static PyObject *arm(PyObject *self, PyObject *arg) {
    (void)self;
    if (!PyLong_CheckExact(arg)) {
        PyErr_SetString(PyExc_TypeError, "integer absolute deadline required");
        return NULL;
    }
    long long deadline = PyLong_AsLongLong(arg);
    if (PyErr_Occurred()) return NULL;
    long long now;
    if (boottime_ns(&now) != 0) return NULL;
    if (deadline <= now || deadline <= 0 || consumed) {
        PyErr_SetString(PyExc_RuntimeError, "fresh future process deadline required");
        return NULL;
    }
    struct itimerspec specification = {0};
    specification.it_value.tv_sec = (time_t)(deadline / NS_PER_SECOND);
    specification.it_value.tv_nsec = (long)(deadline % NS_PER_SECOND);
    if ((uint64_t)specification.it_value.tv_sec !=
        (uint64_t)(deadline / NS_PER_SECOND)) {
        PyErr_SetString(PyExc_OverflowError, "deadline exceeds native time_t");
        return NULL;
    }
    Deadline *value = calloc(1, sizeof(*value));
    if (value == NULL) return PyErr_NoMemory();
    struct sigevent event = {0};
    event.sigev_notify = SIGEV_SIGNAL;
    event.sigev_signo = SIGKILL;
    event.sigev_value.sival_int = 0;
    consumed = 1;
    if (timer_create(CLOCK_BOOTTIME, &event, &value->timer) != 0) {
        int saved = errno;
        free(value);
        errno = saved;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    value->owner = getpid();
    value->deadline = deadline;
    if (timer_settime(value->timer, TIMER_ABSTIME, &specification, NULL) != 0) {
        int saved = errno;
        /* A newly created timer is disarmed if absolute arming failed. */
        (void)timer_delete(value->timer);
        free(value);
        errno = saved;
        return PyErr_SetFromErrno(PyExc_OSError);
    }
    PyObject *capsule = PyCapsule_New(value, CAPSULE, forget_handle);
    if (capsule == NULL) {
        /* No handle can be returned. Leave the fail-closed timer armed. */
        free(value);
    }
    return capsule;
}

static PyObject *check(PyObject *self, PyObject *arg) {
    (void)self;
    Deadline *value = owned_handle(arg);
    if (value == NULL) return NULL;
    if (value->released) {
        PyErr_SetString(PyExc_RuntimeError, "deadline was released");
        return NULL;
    }
    long long now;
    if (boottime_ns(&now) != 0) return NULL;
    struct itimerspec remaining;
    if (timer_gettime(value->timer, &remaining) != 0)
        return PyErr_SetFromErrno(PyExc_OSError);
    if (now >= value->deadline || remaining.it_interval.tv_sec != 0 ||
        remaining.it_interval.tv_nsec != 0 ||
        (remaining.it_value.tv_sec == 0 && remaining.it_value.tv_nsec == 0)) {
        PyErr_SetString(PyExc_RuntimeError, "deadline expired or changed");
        return NULL;
    }
    Py_RETURN_NONE;
}

static PyObject *release(PyObject *self, PyObject *arg) {
    (void)self;
    Deadline *value = owned_handle(arg);
    if (value == NULL) return NULL;
    if (!value->released) {
        if (timer_delete(value->timer) != 0)
            return PyErr_SetFromErrno(PyExc_OSError);
        value->released = 1;
    }
    Py_RETURN_NONE;
}

static PyMethodDef methods[] = {
    {"arm", arm, METH_O, "Arm one absolute BOOTTIME self-SIGKILL deadline."},
    {"check", check, METH_O, "Check the creating process's retained deadline."},
    {"release", release, METH_O, "Release only after confirmed containment."},
    {NULL, NULL, 0, NULL}
};

static struct PyModuleDef module = {
    PyModuleDef_HEAD_INIT, "_bootstrap_deadline", NULL, -1, methods,
    NULL, NULL, NULL, NULL
};

PyMODINIT_FUNC PyInit__bootstrap_deadline(void) {
    return PyModule_Create(&module);
}
