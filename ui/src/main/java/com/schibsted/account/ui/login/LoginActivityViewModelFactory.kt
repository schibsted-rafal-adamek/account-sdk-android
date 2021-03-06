/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */
package com.schibsted.account.ui.login

import android.arch.lifecycle.ViewModel
import android.arch.lifecycle.ViewModelProvider
import com.schibsted.account.ui.AccountUi
import com.schibsted.account.ui.smartlock.SmartlockTask
import java.net.URI

class LoginActivityViewModelFactory(
    private val smartlockTask: SmartlockTask,
    private val redirectUri: URI,
    private val params: AccountUi.Params
) : ViewModelProvider.Factory {

    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        return modelClass.getConstructor(
                smartlockTask::class.java,
                redirectUri::class.java,
                params::class.java).newInstance(smartlockTask, redirectUri, params)
    }
}