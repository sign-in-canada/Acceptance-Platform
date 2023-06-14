addEventListener('DOMContentLoaded', async (loadEvent) => {
    alertCloseButtons = document.querySelectorAll("button.close-alert")
    for (closeButton of alertCloseButtons) {
        closeButton.addEventListener('click', async (clickEvent) => {
            alertBox = document.querySelector("section.alert")
            if (alertBox) {
                alertBox.parentNode.remove()
            }
        }
        )}
    })