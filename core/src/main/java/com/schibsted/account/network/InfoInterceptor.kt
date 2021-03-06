/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.network

import android.os.Build
import com.schibsted.account.AccountService
import com.schibsted.account.BuildConfig
import com.schibsted.account.ClientConfiguration
import com.schibsted.account.common.tracking.UiTracking
import com.schibsted.account.common.util.existsOnClasspath
import okhttp3.Interceptor
import okhttp3.Response

class InfoInterceptor(private val isInternal: Boolean) : Interceptor {
    private val headerName: String = if (isInternal) "User-Agent" else "X-Schibsted-Account-User-Agent"

    override fun intercept(chain: Interceptor.Chain): Response {
        var builder = chain.request()
                .newBuilder()
                .header(headerName, "AccountSdk/${BuildConfig.VERSION_NAME} " +
                        "(Linux; Android ${Build.VERSION.RELEASE}; API ${Build.VERSION.SDK_INT}; " +
                        "${Build.MANUFACTURER}; ${Build.MODEL}) Android (${AccountService.packageName})")

        if (isInternal) {
            builder = builder
                    .header("SDK-Type", "android")
                    .header("SDK-Version", BuildConfig.VERSION_NAME)
                    .header("SDK-Build-Type", BuildConfig.BUILD_TYPE)
                    .header("SDK-Environment", ClientConfiguration.get().environment)
                    .header("SDK-UI-Module", if (existsOnClasspath("com.schibsted.account.ui.AccountUi")) "found" else "missing")

            UiTracking.trackingIdentifier?.let {
                builder = builder.header("pulse-jwe", it)
            }
        }

        return chain.proceed(builder.build())
    }
}
