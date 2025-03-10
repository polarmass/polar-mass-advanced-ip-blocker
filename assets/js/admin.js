jQuery(document).ready(function($) {
    // Show API token instructions
    $('.cfip-show-token-instructions').on('click', function (e) {
        e.preventDefault();
        $('#cfip-token-instructions').fadeIn(300);
        $('body').addClass('cfip-modal-open');
    });

    // Close button functionality
    $('#cfip-close').on('click', function () {
        $('#cfip-token-instructions').fadeOut(300);
        $('body').removeClass('cfip-modal-open');
    });

    // Close modal when clicking outside the content box
    $('#cfip-token-instructions').on('click', function (e) {
        if ($(e.target).is('#cfip-token-instructions')) {
            $('#cfip-token-instructions').fadeOut(300);
            $('body').removeClass('cfip-modal-open');
        }
    });

    // Block IP
    $('#cfip-block-ip').on('click', function() {
        const ip = $('#cfip-ip-input').val().trim();
        if (!ip) {
            alert(cfipAdmin.i18n.enterIp);
            return;
        }

        if (!confirm(cfipAdmin.i18n.confirmBlock)) {
            return;
        }

        $.ajax({
            url: cfipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'cfip_block_ip',
                nonce: cfipAdmin.nonce,
                ip: ip
            },
            beforeSend: function() {
                $('#cfip-block-ip').prop('disabled', true);
            },
            success: function(response) {
                if (response.success) {
                    alert(response.data.message);
                    $('#cfip-ip-input').val('');
                    location.reload();
                } else {
                    alert(response.data.message || cfipAdmin.i18n.error);
                }
            },
            error: function() {
                alert(cfipAdmin.i18n.error);
            },
            complete: function() {
                $('#cfip-block-ip').prop('disabled', false);
            }
        });
    });

    // Unblock IP
    $('#cfip-unblock-ip').on('click', function() {
        const ip = $('#cfip-ip-input').val().trim();
        if (!ip) {
            alert(cfipAdmin.i18n.enterIp);
            return;
        }

        if (!confirm(cfipAdmin.i18n.confirmUnblock)) {
            return;
        }

        $.ajax({
            url: cfipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'cfip_unblock_ip',
                nonce: cfipAdmin.nonce,
                ip: ip
            },
            beforeSend: function() {
                $('#cfip-unblock-ip').prop('disabled', true);
            },
            success: function(response) {
                if (response.success) {
                    alert(response.data.message);
                    $('#cfip-ip-input').val('');
                    location.reload();
                } else {
                    alert(response.data.message || cfipAdmin.i18n.error);
                }
            },
            error: function() {
                alert(cfipAdmin.i18n.error);
            },
            complete: function() {
                $('#cfip-unblock-ip').prop('disabled', false);
            }
        });
    });

    // Filter logs
    $('#cfip-log-level').on('change', function() {
        const level = $(this).val();
        if (level) {
            $('.cfip-log-entries tr').hide();
            $('.cfip-log-entries tr:first').show();
            $('.cfip-log-entries tr').filter(function() {
                return $(this).find('td:eq(1)').text().toLowerCase() === level;
            }).show();
        } else {
            $('.cfip-log-entries tr').show();
        }
    });

    // Export logs
    $('#cfip-export-logs').on('click', function() {
        window.location.href = cfipAdmin.ajaxUrl + '?action=cfip_export_logs&nonce=' + cfipAdmin.nonce;
    });

    // Validate IP input
    $('#cfip-ip-input').on('input', function() {
        const ip = $(this).val().trim();
        const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
        const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

        if (ip && !ipv4Regex.test(ip) && !ipv6Regex.test(ip)) {
            $(this).addClass('error');
        } else {
            $(this).removeClass('error');
        }
    });

    // Sync with Wordfence
    $('#cfip-sync-wordfence').on('click', function() {
        if (!confirm(cfipAdmin.i18n.confirmSync)) {
            return;
        }

        $.ajax({
            url: cfipAdmin.ajaxUrl,
            type: 'POST',
            data: {
                action: 'cfip_sync_wordfence',
                nonce: cfipAdmin.nonce
            },
            beforeSend: function() {
                $('#cfip-sync-wordfence').prop('disabled', true);
            },
            success: function(response) {
                if (response.success) {
                    alert(response.data.message);
                    location.reload();
                } else {
                    alert(response.data.message || cfipAdmin.i18n.error);
                }
            },
            error: function() {
                alert(cfipAdmin.i18n.error);
            },
            complete: function() {
                $('#cfip-sync-wordfence').prop('disabled', false);
            }
        });
    });

    // Check if user is already subscribed
    if (cfipAdmin.isSubscribed) {
        $('.cfip-newsletter-form').hide();
        $('.cfip-newsletter').append('<div class="cfip-newsletter-success">' +
            '<p>You are already subscribed!</p>' +
            '</div>');
        return;
    }

    // Newsletter subscription
    $('.cfip-newsletter-form').on('submit', function (e) {
        e.preventDefault();
        const email = $(this).find('input[type="email"]').val();
        const $message = $('.cfip-newsletter-message');
        const $submitButton = $(this).find('button');
        const $form = $(this);
        const $newsletter = $('.cfip-newsletter');

        $.ajax({
            url: 'https://polarmass.com/wp-json/cfip/v1/newsletter/signup',
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ email: email }),
            beforeSend: function () {
                $submitButton.prop('disabled', true);
                $form.css('opacity', '0.5');
            },
            success: function (response) {
                if (response.success) {
                    $form.fadeOut(300, function () {
                        const successMessage = $('<div class="cfip-newsletter-success">' +
                            '<p>Thank you for subscribing to our newsletter!</p>' +
                            '</div>').hide();
                        $(this).after(successMessage);
                        successMessage.fadeIn(300);
                    });

                    // Update option via AJAX
                    $.ajax({
                        url: cfipAdmin.ajaxUrl,
                        type: 'POST',
                        data: {
                            action: 'cfip_update_newsletter_status',
                            nonce: cfipAdmin.nonce,
                        }
                    });
                } else {
                    $message.removeClass('success').addClass('error').text(response.data.message).fadeIn();
                }
            },
            error: function () {
                $message.removeClass('success').addClass('error').text(cfipAdmin.i18n.error).fadeIn();
            },
            complete: function () {
                $submitButton.prop('disabled', false);
                $form.css('opacity', '1');
                setTimeout(function () {
                    $message.fadeOut();
                }, 5000);
            }
        });
    });
});