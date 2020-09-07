package be.nabu.libs.http.icap;

import be.nabu.libs.http.api.HTTPEntity;

public interface ICAPEntity extends HTTPEntity {
	public HTTPEntity getWrapped();
}
