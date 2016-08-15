#ifndef CP2P_PROTOCOL_TYPE
#define CP2P_PROTOCOL_TYPE TRUE

#include <Python.h>
#include <bytesobject.h>
#include "structmember.h"
#include "base.h"
#include <string>
#include "py_utils.h"

using namespace std;

typedef struct {
    PyObject_HEAD
    protocol prot;
    char *subnet;
    char *encryption;
} protocol_wrapper;

static void protocol_wrapper_dealloc(protocol_wrapper* self)    {
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject *protocol_wrapper_new(PyTypeObject *type, PyObject *args, PyObject *kwds)   {
    protocol_wrapper *self;

    self = (protocol_wrapper *)type->tp_alloc(type, 0);

    return (PyObject *)self;
}

static int protocol_wrapper_init(protocol_wrapper *self, PyObject *args, PyObject *kwds)    {
    const char *sub=NULL, *enc=NULL;
    int sub_size = 0, enc_size = 0;

    static char *kwlist[] = {(char*)"subnet", (char*)"encryption", NULL};

    if (! PyArg_ParseTupleAndKeywords(args, kwds, "s#s#", kwlist, 
                                      &sub, &sub_size, &enc, &enc_size))
        return -1;

    self->prot = protocol(string(sub, sub_size), string(enc, enc_size));
    self->subnet = (char*) self->prot.subnet.c_str();
    self->encryption = (char*) self->prot.encryption.c_str();

    return 0;
}

static PyObject *protocol_id(protocol_wrapper *self)    {
    string cp_str = self->prot.id();
    PyObject *ret = pybytes_from_string(cp_str);
    if (PyErr_Occurred())
        return NULL;
    return ret;
}

static PyMemberDef protocol_wrapper_members[] = {
    {(char*)"subnet", T_STRING, 
        offsetof(protocol_wrapper, subnet),
        READONLY, (char*)"subnet"},
    {(char*)"encryption", T_STRING, 
        offsetof(protocol_wrapper, encryption),
        READONLY, (char*)"encryption"},
    {NULL}  /* Sentinel */
};

static PyMethodDef protocol_wrapper_methods[] = {
    {"id", (PyCFunction)protocol_id, METH_NOARGS,
        "Return the message ID"
    },
    {NULL}  /* Sentinel */
};

static PyTypeObject protocol_wrapper_type = {
    PyVarObject_HEAD_INIT(NULL, 0)
    "protocol",                /* tp_name */
    sizeof(protocol_wrapper),  /* tp_basicsize */
    0,                         /* tp_itemsize */
    (destructor)protocol_wrapper_dealloc,/* tp_dealloc */
    0,                         /* tp_print */
    0,                         /* tp_getattr */
    0,                         /* tp_setattr */
    0,                         /* tp_reserved */
    0,                         /* tp_repr */
    0,                         /* tp_as_number */
    0,                         /* tp_as_sequence */
    0,                         /* tp_as_mapping */
    0,                         /* tp_hash  */
    0,                         /* tp_call */
    0,                         /* tp_str */
    0,                         /* tp_getattro */
    0,                         /* tp_setattro */
    0,                         /* tp_as_buffer */
    Py_TPFLAGS_DEFAULT,        /* tp_flags */
    "C++ implementation of the protocol object",/* tp_doc */
    0,                         /* tp_traverse */
    0,                         /* tp_clear */
    0,                         /* tp_richcompare */
    0,                         /* tp_weaklistoffset */
    0,                         /* tp_iter */
    0,                         /* tp_iternext */
    protocol_wrapper_methods,  /* tp_methods */
    protocol_wrapper_members,  /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)protocol_wrapper_init,/* tp_init */
    0,                         /* tp_alloc */
    protocol_wrapper_new,      /* tp_new */
};

#endif