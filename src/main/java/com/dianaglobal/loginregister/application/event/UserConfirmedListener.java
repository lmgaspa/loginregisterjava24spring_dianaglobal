// src/main/java/com/dianaglobal/loginregister/application/event/UserConfirmedListener.java
package com.dianaglobal.loginregister.application.event;

import com.dianaglobal.loginregister.domain.model.User;

public interface UserConfirmedListener {
    void onUserConfirmed(User user);
}
