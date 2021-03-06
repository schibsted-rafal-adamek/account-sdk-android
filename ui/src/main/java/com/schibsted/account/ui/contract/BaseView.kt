/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.ui.contract

import com.schibsted.account.model.error.ClientError

/**
 * Defines common methods for every views, this class should be implemented by the base fragment
 *
 * @see com.schibsted.account.ui.ui.BaseFragment for instance
 */
interface BaseView<in T> {

    /**
     * Return the state of the fragment, this method should be use to know if an UI update could be
     * performed.
     * Call this method before every intention of UI update
     *
     * @return `true` if the fragment is active, `false` otherwise
     */
    val isActive: Boolean

    /**
     * Ties a Presenter to a view
     *
     * @param presenter
     */
    fun setPresenter(presenter: T)

    fun showErrorDialog(error: ClientError, errorMessage: String? = null)
}
