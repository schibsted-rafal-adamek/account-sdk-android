/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.ui.ui.component

import android.content.Context
import android.util.AttributeSet
import android.view.LayoutInflater
import android.view.View
import android.widget.RelativeLayout
import com.schibsted.account.ui.R
import kotlinx.android.synthetic.main.schacc_loading_button_widget.view.*

class LoadingButton @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
    defStyleAttr: Int = 0
) : RelativeLayout(context, attrs, defStyleAttr) {

    init {
        LayoutInflater.from(context).inflate(R.layout.schacc_loading_button_widget, this)
        val ta = context.obtainStyledAttributes(attrs, R.styleable.LoadingButton, 0, 0)
        try {
            if (ta.hasValue(R.styleable.LoadingButton_text)) {
                button.text = ta.getString(R.styleable.LoadingButton_text)
            }
        } finally {
            ta.recycle()
        }
    }

    fun showProgress() {
        progressBar.visibility = View.VISIBLE
        loadingButtonContainer.isEnabled = false
    }

    fun hideProgress() {
        progressBar.visibility = View.GONE
        loadingButtonContainer.isEnabled = true
    }

    fun setText(text: Int) {
        button.setText(text)
    }

    override fun setOnClickListener(l: OnClickListener?) {
        super.setOnClickListener(l)
        button.setOnClickListener(l)
        progressBar.setOnClickListener(l)
    }
}
