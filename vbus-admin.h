
int vbus_device_create(const char *type, char *name, size_t namelen);

int vbus_device_attr_set(const char *dev, const char *attr, const char *val);
int vbus_device_attr_get(const char *dev, const char *attr,
			 char *val, size_t len);


