/*
 * Copyright (c) 2018 Schibsted Products & Technology AS. Licensed under the terms of the MIT license. See LICENSE in the project root.
 */

package com.schibsted.account.engine.input

import android.os.Parcel
import android.os.Parcelable
import com.schibsted.account.engine.integration.InputProvider
import com.schibsted.account.engine.integration.ResultCallback
import com.schibsted.account.model.NoValue

data class Credentials(val identifier: Identifier, val password: String, val keepLoggedIn: Boolean) : Parcelable {
    constructor(source: Parcel) : this(
            source.readParcelable(Identifier::class.java.classLoader),
            source.readString(),
            source.readInt() != 0
    )

    override fun describeContents() = 0

    override fun writeToParcel(dest: Parcel, flags: Int) = with(dest) {
        writeParcelable(identifier, 0)
        writeString(password)
        writeInt(if (keepLoggedIn) 1 else 0)
    }

    interface Provider {
        /**
         * Called when user credentials are required
         */
        fun onCredentialsRequested(provider: InputProvider<Credentials>)
    }

    companion object {
        @JvmField
        val CREATOR: Parcelable.Creator<Credentials> = object : Parcelable.Creator<Credentials> {
            override fun createFromParcel(source: Parcel): Credentials = Credentials(source)
            override fun newArray(size: Int): Array<Credentials?> = arrayOfNulls(size)
        }

        internal fun request(provider: Provider, onProvided: (Credentials, ResultCallback<NoValue>) -> Unit) {
            provider.onCredentialsRequested(InputProvider(onProvided))
        }
    }
}
