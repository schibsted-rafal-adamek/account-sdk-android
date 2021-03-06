/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.ui.login.screen.inbox

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.schibsted.account.engine.input.Identifier
import com.schibsted.account.ui.R
import com.schibsted.account.ui.ui.BaseFragment
import kotlinx.android.synthetic.main.schacc_inbox_fragment_layout.*

private const val KEY_IDENTIFIER = "KEY_IDENTIFIER"

class InboxFragment : BaseFragment() {

    private var identifier: Identifier? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val arg = savedInstanceState ?: arguments
        identifier = arg?.getParcelable(KEY_IDENTIFIER)
    }

    override fun onCreateView(inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?): View? {
        return inflater.inflate(R.layout.schacc_inbox_fragment_layout, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        inbox_change_identifier.setOnClickListener {
            navigationListener?.onNavigateBackRequested()
        }
        inbox_information.text = getString(R.string.schacc_inbox_information, identifier?.identifier)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putParcelable(KEY_IDENTIFIER, identifier)
    }

    companion object {
        fun newInstance(identifier: Identifier): InboxFragment {
            val fragment = InboxFragment()
            val arg = Bundle()
            arg.putParcelable(KEY_IDENTIFIER, identifier)
            fragment.arguments = arg
            return fragment
        }
    }
}
