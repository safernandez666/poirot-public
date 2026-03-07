/**
 * Poirot Landing Page - JavaScript
 * Mobile menu, scroll animations, smooth scrolling
 */

(function() {
  'use strict';

  // ============================================
  // Mobile Navigation
  // ============================================
  
  const navToggle = document.querySelector('.nav-toggle');
  const navMenu = document.querySelector('.nav-menu');
  
  if (navToggle && navMenu) {
    navToggle.addEventListener('click', function() {
      navMenu.classList.toggle('active');
      navToggle.classList.toggle('active');
      document.body.classList.toggle('nav-open');
    });
    
    // Close menu when clicking a link
    navMenu.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', function() {
        navMenu.classList.remove('active');
        navToggle.classList.remove('active');
        document.body.classList.remove('nav-open');
      });
    });
  }

  // ============================================
  // Smooth Scroll
  // ============================================
  
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const targetId = this.getAttribute('href');
      
      if (targetId === '#') return;
      
      const targetElement = document.querySelector(targetId);
      
      if (targetElement) {
        e.preventDefault();
        
        const navHeight = document.querySelector('.navbar').offsetHeight;
        const targetPosition = targetElement.getBoundingClientRect().top + window.pageYOffset - navHeight;
        
        window.scrollTo({
          top: targetPosition,
          behavior: 'smooth'
        });
      }
    });
  });

  // ============================================
  // Scroll Reveal Animation
  // ============================================
  
  const revealElements = document.querySelectorAll(
    '.section-header, .feature-card, .feature-block, .source-card, ' +
    '.integration-card, .deploy-card, .comparison-container, .comparison-stats'
  );
  
  const revealObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
        revealObserver.unobserve(entry.target);
      }
    });
  }, {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  });
  
  revealElements.forEach((el, index) => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(30px)';
    el.style.transition = `opacity 0.6s ease ${index * 0.05}s, transform 0.6s ease ${index * 0.05}s`;
    revealObserver.observe(el);
  });

  // ============================================
  // Navbar Scroll Effect
  // ============================================
  
  const navbar = document.querySelector('.navbar');
  let lastScroll = 0;
  
  window.addEventListener('scroll', function() {
    const currentScroll = window.pageYOffset;
    
    // Add/remove scrolled class for background
    if (currentScroll > 50) {
      navbar.style.background = 'rgba(10, 10, 15, 0.95)';
      navbar.style.boxShadow = '0 4px 20px rgba(0, 0, 0, 0.3)';
    } else {
      navbar.style.background = 'rgba(10, 10, 15, 0.8)';
      navbar.style.boxShadow = 'none';
    }
    
    lastScroll = currentScroll;
  }, { passive: true });

  // ============================================
  // Confidence Bar Animation
  // ============================================
  
  const confidenceBars = document.querySelectorAll('.confidence-bar');
  
  const barObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const bar = entry.target;
        const value = bar.style.getPropertyValue('--value');
        bar.style.setProperty('--value', '0%');
        
        setTimeout(() => {
          bar.style.setProperty('--value', value);
        }, 100);
        
        barObserver.unobserve(bar);
      }
    });
  }, { threshold: 0.5 });
  
  confidenceBars.forEach(bar => barObserver.observe(bar));

  // ============================================
  // Dashboard Preview Animation
  // ============================================
  
  const alertCards = document.querySelectorAll('.alert-card');
  
  alertCards.forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateX(-20px)';
    card.style.transition = `opacity 0.5s ease ${index * 0.2}s, transform 0.5s ease ${index * 0.2}s`;
  });
  
  const dashboardObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        alertCards.forEach(card => {
          card.style.opacity = '1';
          card.style.transform = 'translateX(0)';
        });
        dashboardObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.3 });
  
  const dashboardPreview = document.querySelector('.dashboard-preview');
  if (dashboardPreview) {
    dashboardObserver.observe(dashboardPreview);
  }

  // ============================================
  // Pattern Tags Animation
  // ============================================
  
  const patternTags = document.querySelectorAll('.pattern-tag');
  
  patternTags.forEach((tag, index) => {
    tag.style.opacity = '0';
    tag.style.transform = 'scale(0.8)';
    tag.style.transition = `opacity 0.4s ease ${index * 0.03}s, transform 0.4s ease ${index * 0.03}s`;
  });
  
  const patternsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        patternTags.forEach(tag => {
          tag.style.opacity = '1';
          tag.style.transform = 'scale(1)';
        });
        patternsObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.3 });
  
  const patternsGrid = document.querySelector('.patterns-grid');
  if (patternsGrid) {
    patternsObserver.observe(patternsGrid);
  }

  // ============================================
  // Comparison Counter Animation
  // ============================================
  
  function animateCounter(element, target, duration = 1500) {
    const start = 0;
    const increment = target / (duration / 16);
    let current = start;
    
    const timer = setInterval(() => {
      current += increment;
      if (current >= target) {
        element.textContent = target.toLocaleString();
        clearInterval(timer);
      } else {
        element.textContent = Math.floor(current).toLocaleString();
      }
    }, 16);
  }
  
  const comparisonObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const beforeValue = entry.target.querySelector('.comparison-before .metric-value');
        const afterValue = entry.target.querySelector('.comparison-after .metric-value');
        
        if (beforeValue) {
          const target = parseInt(beforeValue.textContent.replace(/,/g, ''));
          beforeValue.textContent = '0';
          setTimeout(() => animateCounter(beforeValue, target), 100);
        }
        
        if (afterValue) {
          const target = parseInt(afterValue.textContent.replace(/,/g, ''));
          afterValue.textContent = '0';
          setTimeout(() => animateCounter(afterValue, target), 500);
        }
        
        comparisonObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });
  
  const comparisonContainer = document.querySelector('.comparison-container');
  if (comparisonContainer) {
    comparisonObserver.observe(comparisonContainer);
  }

  // ============================================
  // Hero Stats Counter Animation
  // ============================================
  
  const heroStats = document.querySelectorAll('.stat-value');
  
  const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const stat = entry.target;
        const text = stat.textContent;
        const hasPlus = text.includes('+');
        const hasPercent = text.includes('%');
        const numValue = parseInt(text.replace(/[^0-9]/g, ''));
        
        if (!isNaN(numValue)) {
          stat.textContent = '0';
          
          let current = 0;
          const increment = numValue / 30;
          const timer = setInterval(() => {
            current += increment;
            if (current >= numValue) {
              let final = numValue.toString();
              if (hasPlus) final += '+';
              if (hasPercent) final += '%';
              stat.textContent = final;
              clearInterval(timer);
            } else {
              stat.textContent = Math.floor(current);
            }
          }, 50);
        }
        
        statsObserver.unobserve(stat);
      }
    });
  }, { threshold: 0.5 });
  
  heroStats.forEach(stat => statsObserver.observe(stat));

  // ============================================
  // External Links - Open in New Tab
  // ============================================
  
  document.querySelectorAll('a[href^="http"]').forEach(link => {
    if (!link.hasAttribute('target')) {
      link.setAttribute('target', '_blank');
      link.setAttribute('rel', 'noopener noreferrer');
    }
  });

  // ============================================
  // Add CSS for Mobile Menu
  // ============================================
  
  const mobileMenuStyles = document.createElement('style');
  mobileMenuStyles.textContent = `
    @media (max-width: 767px) {
      .nav-menu {
        position: fixed;
        top: 72px;
        left: 0;
        right: 0;
        background: rgba(10, 10, 15, 0.98);
        backdrop-filter: blur(20px);
        flex-direction: column;
        padding: 24px;
        gap: 16px;
        border-bottom: 1px solid var(--color-border);
        transform: translateY(-100%);
        opacity: 0;
        visibility: hidden;
        transition: all 0.3s ease;
        z-index: 999;
      }
      
      .nav-menu.active {
        transform: translateY(0);
        opacity: 1;
        visibility: visible;
      }
      
      .nav-toggle.active span:nth-child(1) {
        transform: rotate(45deg) translate(5px, 5px);
      }
      
      .nav-toggle.active span:nth-child(2) {
        opacity: 0;
      }
      
      .nav-toggle.active span:nth-child(3) {
        transform: rotate(-45deg) translate(5px, -5px);
      }
      
      body.nav-open {
        overflow: hidden;
      }
    }
  `;
  document.head.appendChild(mobileMenuStyles);

  console.log('🎩 Poirot Landing Page - Ready');
})();
