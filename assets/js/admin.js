jQuery(document).ready(function ($) {
    // Show API token instructions
    $('.pmip-show-token-instructions').on('click', function (e) {
        e.preventDefault()
        $('#pmip-token-instructions').fadeIn(300)
        $('body').addClass('pmip-modal-open')
    })

    // Close button functionality
    $('#pmip-close').on('click', function () {
        $('#pmip-token-instructions').fadeOut(300)
        $('body').removeClass('pmip-modal-open')
    })

    // Close modal when clicking outside the content box
    $('#pmip-token-instructions').on('click', function (e) {
        if ($(e.target).is('#pmip-token-instructions')) {
            $('#pmip-token-instructions').fadeOut(300)
            $('body').removeClass('pmip-modal-open')
        }
    })

    // Block IP
    $('#pmip-block-ip').on('click', function () {
        const ip = $('#pmip-ip-input').val().trim()
        if (!ip) {
            alert(pmipAdmin.i18n.enterIp)
            return
        }

        if (!confirm(pmipAdmin.i18n.confirmBlock)) {
            return
        }

        $.ajax({
            url: pmipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'pmip_block_ip',
                nonce: pmipAdmin.nonce,
                ip: ip,
            },
            beforeSend: function () {
                $('#pmip-block-ip').prop('disabled', true)
            },
            success: function (response) {
                if (response.success) {
                    alert(response.data.message)
                    $('#pmip-ip-input').val('')
                    location.reload()
                } else {
                    alert(response.data.message || pmipAdmin.i18n.error)
                }
            },
            error: function () {
                alert(pmipAdmin.i18n.error)
            },
            complete: function () {
                $('#pmip-block-ip').prop('disabled', false)
            },
        })
    })

    // Unblock IP
    $('#pmip-unblock-ip').on('click', function () {
        const ip = $('#pmip-ip-input').val().trim()
        if (!ip) {
            alert(pmipAdmin.i18n.enterIp)
            return
        }

        if (!confirm(pmipAdmin.i18n.confirmUnblock)) {
            return
        }

        $.ajax({
            url: pmipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'pmip_unblock_ip',
                nonce: pmipAdmin.nonce,
                ip: ip,
            },
            beforeSend: function () {
                $('#pmip-unblock-ip').prop('disabled', true)
            },
            success: function (response) {
                if (response.success) {
                    alert(response.data.message)
                    $('#pmip-ip-input').val('')
                    location.reload()
                } else {
                    alert(response.data.message || pmipAdmin.i18n.error)
                }
            },
            error: function () {
                alert(pmipAdmin.i18n.error)
            },
            complete: function () {
                $('#pmip-unblock-ip').prop('disabled', false)
            },
        })
    })

    // Filter logs
    $('#pmip-log-level').on('change', function () {
        const level = $(this).val()
        if (level) {
            $('.pmip-log-entries tr').hide()
            $('.pmip-log-entries tr:first').show()
            $('.pmip-log-entries tr')
                .filter(function () {
                    return $(this).find('td:eq(1)').text().toLowerCase() === level
                })
                .show()
        } else {
            $('.pmip-log-entries tr').show()
        }
    })

    // Export logs
    $('#pmip-export-logs').on('click', function () {
        window.location.href = pmipAdmin.ajaxUrl + '?action=pmip_export_logs&nonce=' + pmipAdmin.nonce
    })

    // Validate IP input
    $('#pmip-ip-input').on('input', function () {
        const ip = $(this).val().trim()
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/

        if (ip && !ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            $(this).addClass('error')
        } else {
            $(this).removeClass('error')
        }
    })

    // Sync with Wordfence
    $('#pmip-sync-wordfence').on('click', function () {
        if (!confirm(pmipAdmin.i18n.confirmSync)) {
            return
        }

        $.ajax({
            url: pmipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'pmip_sync_wordfence',
                nonce: pmipAdmin.nonce,
            },
            beforeSend: function () {
                $('#pmip-sync-wordfence').prop('disabled', true)
            },
            success: function (response) {
                if (response.success) {
                    alert(response.data.message)
                    location.reload()
                } else {
                    alert(response.data.message || pmipAdmin.i18n.error)
                }
            },
            error: function () {
                alert(pmipAdmin.i18n.error)
            },
            complete: function () {
                $('#pmip-sync-wordfence').prop('disabled', false)
            },
        })
    })

    // Check if user is already subscribed
    if (pmipAdmin.isSubscribed) {
        $('.pmip-newsletter-form').hide()
        $('.pmip-newsletter').append('<div class="pmip-newsletter-success">' + '<p>You are already subscribed!</p>' + '</div>')
        return
    }

    // Newsletter subscription
    $('.pmip-newsletter-form').on('submit', function (e) {
        e.preventDefault()
        const email = $(this).find('input[type="email"]').val()
        const $message = $('.pmip-newsletter-message')
        const $submitButton = $(this).find('button')
        const $form = $(this)
        const $newsletter = $('.pmip-newsletter')

        $.ajax({
            url: 'https://polarmass.com/wp-json/pmip/v1/newsletter/signup',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: email }),
            beforeSend: function () {
                $submitButton.prop('disabled', true)
                $form.css('opacity', '0.5')
            },
            success: function (response) {
                if (response.success) {
                    $form.fadeOut(300, function () {
                        const successMessage = $(
                            '<div class="pmip-newsletter-success">' + '<p>Thank you for subscribing to our newsletter!</p>' + '</div>'
                        ).hide()
                        $(this).after(successMessage)
                        successMessage.fadeIn(300)
                    })

                    // Update option via AJAX
                    $.ajax({
                        url: pmipAdmin.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'pmip_update_newsletter_status',
                            nonce: pmipAdmin.nonce,
                        },
                    })
                } else {
                    $message.removeClass('success').addClass('error').text(response.data.message).fadeIn()
                }
            },
            error: function () {
                $message.removeClass('success').addClass('error').text(pmipAdmin.i18n.error).fadeIn()
            },
            complete: function () {
                $submitButton.prop('disabled', false)
                $form.css('opacity', '1')
                setTimeout(function () {
                    $message.fadeOut()
                }, 5000)
            },
        })
    })
})
