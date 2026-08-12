/**
 * Shared WebSocket progress handler for bulk operations.
 * Requires BULK_PROGRESS_CONFIG to be set before this script loads:
 *   window.BULK_PROGRESS_CONFIG = {
 *     sessionId: '<session-id>',
 *     processingMessage: 'Processing...',
 *     completedMessage: 'Complete',
 *     connectionLostMessage: 'Connection lost...',
 *     initialBarClass: 'bg-danger'  // optional — removed from bar on completion
 *   };
 */
(function () {
    var cfg = window.BULK_PROGRESS_CONFIG || {};
    var socket = io();

    socket.on('connect', function () {
        socket.emit('join', { room: cfg.sessionId });
        document.getElementById('statusMessage').textContent = cfg.processingMessage || 'Processing...';
    });

    socket.on('bulk_progress', function (data) {
        var bar = document.getElementById('progressBar');
        var status = document.getElementById('statusMessage');
        var count = document.getElementById('progressCount');

        if (data.phase === 'progress') {
            var pct = data.percent + '%';
            bar.style.width = pct;
            bar.textContent = pct;
            count.textContent = data.completed + ' / ' + data.total;

            if (data.current) {
                var item = document.createElement('div');
                var isOk = data.current.status === 'success';
                item.className = 'alert py-2 mb-1 ' + (isOk ? 'alert-success' : 'alert-danger');
                item.innerHTML = (isOk ? '<i class="bi bi-check-circle"></i> ' : '<i class="bi bi-x-circle"></i> ') +
                    data.current.label + (data.current.error ? ' \u2014 ' + data.current.error : '');
                document.getElementById('resultsList').appendChild(item);
            }
        } else if (data.phase === 'completed') {
            bar.style.width = '100%';
            bar.textContent = '100%';
            bar.classList.remove('progress-bar-animated');
            if (cfg.initialBarClass) { bar.classList.remove(cfg.initialBarClass); }
            bar.classList.add(data.failed > 0 ? 'bg-warning' : 'bg-success');
            status.textContent = cfg.completedMessage || 'Complete';
            count.textContent = data.total + ' / ' + data.total;

            document.getElementById('successCount').textContent = data.succeeded;
            document.getElementById('failCount').textContent = data.failed;
            document.getElementById('completionSummary').classList.remove('d-none');

            socket.disconnect();
        }
    });

    socket.on('connect_error', function () {
        document.getElementById('statusMessage').textContent =
            cfg.connectionLostMessage || 'Connection lost. Results may still be processing.';
    });
}());
