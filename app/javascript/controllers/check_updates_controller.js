import { Controller } from "@hotwired/stimulus"
import { createConsumer } from "@rails/actioncable"

export default class extends Controller {
  static values = { checkId: Number }

  connect() {
    this.consumer = createConsumer()
    this.subscription = this.consumer.subscriptions.create(
      {
        channel: "DomainCheckChannel",
        id: this.checkIdValue
      },
      {
        received: (data) => {
          if (data.status === "completed" || data.status === "failed") {
            // Reload the page to show updated results
            window.location.reload()
          }
        }
      }
    )
  }

  disconnect() {
    if (this.subscription) {
      this.subscription.unsubscribe()
    }
    if (this.consumer) {
      this.consumer.disconnect()
    }
  }
}

