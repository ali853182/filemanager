<template>
  <div class="modal-card comment-search">
    <header class="modal-card-head">
      <p class="modal-card-title">
        {{ lang('Comment search') }}
      </p>
      <b-loading :is-full-page="false" :active.sync="searching" />
    </header>
    <section class="modal-card-body">
      <b-input
        ref="input"
        v-model="term"
        :placeholder="lang('Search comments')"
        @input="search"
      />
      <br>
      <p v-if="error" class="has-text-danger">
        {{ error }}
      </p>
      <p v-else-if="searched && ! results.length" class="has-text-grey">
        {{ lang('No comments found') }}
      </p>
      <ul class="comment-search-results">
        <li v-for="(hit, index) in results" :key="index">
          <a @click="select(hit)">
            <span class="is-family-monospace">{{ hit.path }}</span>
          </a>
          <div class="has-text-grey">
            <strong>{{ hit.user }}</strong>
            <span>({{ hit.role }})</span>
            <span>&mdash; {{ formatTimestamp(hit.created_at) }}</span>
          </div>
          <p class="comment-search-snippet">
            {{ hit.snippet }}
          </p>
        </li>
      </ul>
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
import _ from 'lodash'
import api from '../../api/api'

export default {
  name: 'CommentSearch',
  data() {
    return {
      term: '',
      results: [],
      searching: false,
      searched: false,
      error: '',
    }
  },
  mounted() {
    this.$refs.input.focus()
  },
  methods: {
    search: _.debounce(function(term) {
      const query = (term || '').trim()
      this.error = ''
      if (! query) {
        this.results = []
        this.searched = false
        return
      }
      this.searching = true
      api.searchComments({ q: query })
        .then(data => {
          this.searching = false
          this.searched = true
          this.results = data.results || []
        })
        .catch(error => {
          this.searching = false
          this.searched = true
          this.results = []
          if (error && error.response && error.response.status == 403) {
            this.error = this.lang('Not Allowed')
            return
          }
          this.error = this.lang('Unable to search comments')
          this.handleError(error)
        })
    }, 500),
    select(hit) {
      this.$emit('selected', hit)
      this.$parent.close()
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
.comment-search-results li {
  padding: 0.5rem 0;
  border-bottom: 1px solid #f0f0f0;
}
.comment-search-snippet {
  white-space: pre-wrap;
  word-break: break-word;
  margin-top: 0.25rem;
}
</style>
