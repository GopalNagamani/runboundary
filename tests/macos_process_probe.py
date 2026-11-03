"""Synthetic Seatbelt diagnostic payload; never prints process contents."""
import ctypes
import errno
import json
import sys

lib = ctypes.CDLL(None, use_errno=True)
lib.sysctl.argtypes = [
    ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t,
]
lib.sysctl.restype = ctypes.c_int
results = []
for operation in (38, 49):  # KERN_PROCARGS and KERN_PROCARGS2
    mib = (ctypes.c_int * 3)(1, operation, int(sys.argv[1]))
    buf = ctypes.create_string_buffer(1024 * 1024)
    size = ctypes.c_size_t(len(buf))
    ctypes.set_errno(0)
    result = lib.sysctl(mib, 3, buf, ctypes.byref(size), None, 0)
    error = ctypes.get_errno()
    data = buf.raw[:min(size.value, len(buf))]
    results.append({
        "operation": operation, "result": result, "errno": error,
        "argument_visible": b"SYNTHETIC_HOST_ARGUMENT=not-real" in data,
        "environment_visible": b"SYNTHETIC_HOST_TOKEN=not-real" in data,
        "denied": result == -1 and error in (errno.EPERM, errno.EACCES),
    })
print(json.dumps(results))
