package com.dianaglobal.loginregister.adapter.out.persistence;

import com.dianaglobal.loginregister.adapter.out.persistence.entity.ConfirmResendThrottleEntity;
import org.springframework.data.mongodb.repository.MongoRepository;

public interface ConfirmResendThrottleRepository extends MongoRepository<ConfirmResendThrottleEntity, String> {}
