/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.model.error

import com.schibsted.account.common.util.Logger

internal data class GenericError(val message: () -> String, val details: (() -> String)? = null, val throwable: Throwable? = null) : InternalError {
    init {
        Logger.debug("${message()} :: ${details?.invoke()}", throwable)
    }

    override fun toClientError(): ClientError =
            ClientError(ClientError.ErrorType.GENERIC_ERROR, "${message()} :: ${details?.invoke()}")
}
