/**
 * Copyright 2018 Priyank Vasa
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.pvryan.easycryptsample.main

import android.support.v7.widget.RecyclerView
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import com.pvryan.easycryptsample.R
import com.pvryan.easycryptsample.data.Card
import kotlinx.android.synthetic.main.card_view_main.view.*

class MainAdapter(private val mDataset: ArrayList<Card>) : RecyclerView.Adapter<MainAdapter.ViewHolder>() {

    override fun onBindViewHolder(holder: ViewHolder, position: Int) {
        holder.bindItems(mDataset[position])
    }

    override fun getItemCount() = mDataset.size

    override fun onCreateViewHolder(parent: ViewGroup?, viewType: Int): ViewHolder {
        val v = LayoutInflater.from(parent?.context).inflate(R.layout.card_view_main, parent, false)
        return ViewHolder(v)
    }

    class ViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {

        fun bindItems(card: Card) {
            itemView.tvTitle.text = card.title
            itemView.tvDesc.text = card.desc
            itemView.buttonAction1.text = card.actionText1
            itemView.buttonAction2.text = card.actionText2

            if (card.action1 == null) {
                itemView.buttonAction1.visibility = View.GONE
            } else {
                itemView.buttonAction1.setOnClickListener(card.action1)
            }
            if (card.action2 == null) {
                itemView.buttonAction2.visibility = View.GONE
            } else {
                itemView.buttonAction2.setOnClickListener(card.action2)
            }
        }
    }

}
