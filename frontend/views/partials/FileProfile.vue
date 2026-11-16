<template>
  <div class="modal-card file-profile">
    <header class="modal-card-head">
      <p class="modal-card-title">
        {{ lang('File profile') }}
      </p>
      <b-loading :is-full-page="false" :active.sync="loading" />
    </header>
    <section class="modal-card-body">
      <p class="file-profile-path">
        {{ path }}
      </p>

      <b-message v-if="error" type="is-danger" :closable="false">
        {{ error }}
      </b-message>

      <b-tabs v-if="profile" v-model="activeTab">
        <b-tab-item :label="lang('Overview')">
          <table class="table is-fullwidth is-narrow">
            <tbody>
              <tr>
                <th>{{ lang('Name') }}</th>
                <td>{{ profile.file.path }}</td>
              </tr>
              <tr>
                <th>{{ lang('Type') }}</th>
                <td>{{ profile.file.type == 'dir' ? lang('Folder') : lang('File') }}</td>
              </tr>
              <tr>
                <th>{{ lang('Size') }}</th>
                <td>{{ profile.file.size === null ? '' : formatBytes(profile.file.size) }}</td>
              </tr>
              <tr>
                <th>{{ lang('File id') }}</th>
                <td class="is-family-monospace">
                  {{ profile.file.file_id || lang('Not available') }}
                </td>
              </tr>
              <tr>
                <th>{{ lang('Permissions') }}</th>
                <td>{{ profile.file.permissions === null ? '' : profile.file.permissions }}</td>
              </tr>
              <tr>
                <th>{{ lang('Modified') }}</th>
                <td>{{ formatTimestamp(profile.file.modified_at) }}</td>
              </tr>
              <tr v-if="profile.file.deleted_at">
                <th>{{ lang('Deleted') }}</th>
                <td>{{ formatTimestamp(profile.file.deleted_at) }}</td>
              </tr>
            </tbody>
          </table>

          <h4 class="file-profile-heading">
            {{ lang('Summary') }}
          </h4>
          <table class="table is-fullwidth is-narrow">
            <tbody>
              <tr>
                <th>{{ lang('Created') }}</th>
                <td>{{ formatTimestamp(profile.summary.created_at) }}</td>
              </tr>
              <tr>
                <th>{{ lang('Created by') }}</th>
                <td>{{ profile.summary.created_by || '' }}</td>
              </tr>
              <tr>
                <th>{{ lang('Last modified') }}</th>
                <td>{{ formatTimestamp(profile.summary.last_modified_at) }}</td>
              </tr>
              <tr>
                <th>{{ lang('Last modified by') }}</th>
                <td>{{ profile.summary.last_modified_by || '' }}</td>
              </tr>
              <tr>
                <th>{{ lang('Events') }}</th>
                <td>{{ profile.summary.event_count }}</td>
              </tr>
              <tr>
                <th>{{ lang('Comments') }}</th>
                <td>{{ profile.summary.comment_count }}</td>
              </tr>
            </tbody>
          </table>
        </b-tab-item>

        <b-tab-item :label="lang('History')">
          <p v-if="!profile.history.length" class="has-text-grey">
            {{ lang('No history yet') }}
          </p>
          <ul v-else class="file-profile-history">
            <li v-for="event in profile.history" :key="event.event_id">
              <span class="is-family-monospace">{{ formatTimestamp(event.ts) }}</span>
              &mdash;
              <strong>{{ event.action }}</strong>
              <span class="has-text-grey">({{ event.result }})</span>
              &mdash;
              {{ event.user }}
              <template v-if="event.destination">
                &rarr; {{ event.destination }}
              </template>
              <span v-if="event.ip" class="has-text-grey">[{{ event.ip }}]</span>
            </li>
          </ul>
        </b-tab-item>

        <b-tab-item :label="lang('Comments')">
          <b-field :message="commentError">
            <b-input
              v-model="newComment"
              type="textarea"
              :placeholder="lang('Write a comment')"
              :maxlength="5000"
              rows="3"
            />
          </b-field>
          <p class="has-text-right">
            <button
              class="button is-small is-primary"
              type="button"
              :disabled="submitting || ! newComment.trim()"
              @click="addComment"
            >
              {{ lang('Add comment') }}
            </button>
          </p>

          <p v-if="!comments.length" class="has-text-grey">
            {{ lang('No comments yet') }}
          </p>
          <ul v-else class="file-profile-comments">
            <li v-for="comment in comments" :key="comment.comment_id">
              <div class="is-flex is-justify-between">
                <span>
                  <strong>{{ comment.user }}</strong>
                  <span class="has-text-grey">({{ comment.role }})</span>
                  <span class="has-text-grey">&mdash; {{ formatTimestamp(comment.created_at) }}</span>
                </span>
                <a v-if="canDelete(comment)" class="has-text-danger" @click="removeComment(comment)">
                  {{ lang('Delete') }}
                </a>
              </div>
              <p class="file-profile-comment-body">
                {{ comment.body }}
              </p>
            </li>
          </ul>
        </b-tab-item>
      </b-tabs>
    </section>
    <footer class="modal-card-foot">
      <button class="button" type="button" @click="$parent.close()">
        {{ lang('Close') }}
      </button>
    </footer>
  </div>
</template>

<script>
import moment from 'moment'
import api from '../../api/api'

export default {
  name: 'FileProfile',
  props: {
    path: {
      type: String,
      required: true,
    },
    type: {
      type: String,
      default: 'file',
    },
    initialTab: {
      type: Number,
      default: 0,
    },
  },
  data() {
    return {
      loading: false,
      error: '',
      profile: null,
      comments: [],
      activeTab: this.initialTab,
      newComment: '',
      commentError: '',
      submitting: false,
    }
  },
  mounted() {
    this.load()
  },
  methods: {
    load() {
      this.loading = true
      this.error = ''
      api.getFileProfile({ path: this.path })
        .then(profile => {
          this.loading = false
          this.profile = profile
          this.comments = profile.comments || []
        })
        .catch(error => {
          this.loading = false
          this.profile = null
          if (error && error.response && error.response.status == 403) {
            this.error = this.lang('Not Allowed')
            return
          }
          if (error && error.response && error.response.status == 404) {
            this.error = this.lang('Not Found')
            return
          }
          this.error = this.lang('Unable to load the file profile')
          this.handleError(error)
        })
    },
    addComment() {
      const text = this.newComment.trim()
      this.commentError = ''
      if (! text) {
        this.commentError = this.lang('Comment must not be empty')
        return
      }
      if (text.length > 5000) {
        this.commentError = this.lang('Comment is too long')
        return
      }
      this.submitting = true
      api.addComment({
        path: this.path,
        text: text,
        type: this.type,
      })
        .then(() => {
          this.submitting = false
          this.newComment = ''
          this.load()
        })
        .catch(error => {
          this.submitting = false
          if (error && error.response && error.response.status == 422) {
            this.commentError = this.lang('Comment is invalid')
            return
          }
          this.handleError(error)
        })
    },
    removeComment(comment) {
      this.$dialog.confirm({
        message: this.lang('Are you sure you want to do this?'),
        type: 'is-danger',
        cancelText: this.lang('Cancel'),
        confirmText: this.lang('Delete'),
        onConfirm: () => {
          api.deleteComment({ comment_id: comment.comment_id })
            .then(() => {
              this.load()
            })
            .catch(error => this.handleError(error))
        },
      })
    },
    canDelete(comment) {
      return this.is('admin') || comment.user === this.$store.state.user.username
    },
    formatTimestamp(value) {
      if (! value) {
        return ''
      }
      const parsed = moment(value)
      return parsed.isValid() ? parsed.format('YY/MM/DD HH:mm:ss') : String(value)
    },
  },
}
</script>

<style scoped>
.file-profile-path {
  font-family: monospace;
  word-break: break-all;
  margin-bottom: 1rem;
}
.file-profile-heading {
  font-weight: bold;
  margin: 1rem 0 0.5rem 0;
}
.file-profile-history li,
.file-profile-comments li {
  padding: 0.5rem 0;
  border-bottom: 1px solid #f0f0f0;
}
.file-profile-comment-body {
  white-space: pre-wrap;
  word-break: break-word;
  margin-top: 0.25rem;
}
</style>
