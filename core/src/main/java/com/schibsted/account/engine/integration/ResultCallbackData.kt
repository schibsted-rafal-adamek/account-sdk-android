/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.engine.integration

import com.schibsted.account.model.error.ClientError

interface ResultCallbackData<in T> {
    fun onSuccess(result: T)
    fun onError(error: ClientError)

    companion object {
        fun <T> fromLambda(onErrorFun: (ClientError) -> Unit, onSuccessFun: (T) -> Unit): ResultCallbackData<T> {
            return object : ResultCallbackData<T> {
                override fun onSuccess(result: T) {
                    onSuccessFun(result)
                }

                override fun onError(error: ClientError) {
                    onErrorFun(error)
                }
            }
        }
    }
}