/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.ui.login;

import com.schibsted.account.ui.ui.FlowFragment;

/**
 * a listener of the keyboard visibility
 */
public interface KeyboardVisibilityListener {

    /**
     * this method has to be called when the keyboard visibility has changed.
     *
     * @param isOpen <code>true</code> if the keyboard is now visible <code>false</code> otherwise.
     * @see FlowFragment#onVisibilityChanged(boolean)
     */
    void onVisibilityChanged(boolean isOpen);
}
