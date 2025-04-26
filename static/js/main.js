/**
 * Main JavaScript file for IoT Network Traffic Analyzer
 */

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Initialize popovers
    var popoverTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="popover"]'));
    var popoverList = popoverTriggerList.map(function (popoverTriggerEl) {
        return new bootstrap.Popover(popoverTriggerEl);
    });
    
    // Auto-hide alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-important)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Add any active state handling for the navbar
    var currentLocation = window.location.pathname;
    var navLinks = document.querySelectorAll('.navbar-nav .nav-link');
    
    navLinks.forEach(function(link) {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('active');
        }
    });
    
    // File input handling for upload page
    var fileInput = document.getElementById('pcapFile');
    if (fileInput) {
        fileInput.addEventListener('change', function() {
            var fileDetails = document.getElementById('fileDetails');
            var fileName = document.getElementById('fileName');
            var fileSize = document.getElementById('fileSize');
            
            if (this.files && this.files[0]) {
                var file = this.files[0];
                
                // Display file details
                fileDetails.classList.remove('d-none');
                fileName.textContent = 'File: ' + file.name;
                
                // Format file size
                var size = file.size;
                var units = ['B', 'KB', 'MB', 'GB'];
                var unitIndex = 0;
                
                while (size > 1024 && unitIndex < units.length - 1) {
                    size /= 1024;
                    unitIndex++;
                }
                
                fileSize.textContent = 'Size: ' + size.toFixed(2) + ' ' + units[unitIndex];
            } else {
                fileDetails.classList.add('d-none');
            }
        });
    }
    
    // Form validation on submit
    var forms = document.querySelectorAll('.needs-validation');
    Array.prototype.slice.call(forms).forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        }, false);
    });
    
    // Fix for the Block All form in results page
    var blockAllForm = document.getElementById('blockAllForm');
    if (blockAllForm) {
        blockAllForm.action = window.location.pathname.replace('/view_scan/', '/block_all_ips/');
    }
});
