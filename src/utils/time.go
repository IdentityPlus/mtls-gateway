package utils

import (
	"crypto/x509"
	"math"
	"strconv"
	"time"
)

func FormatDuration(start, end time.Time) string {
	years, months, days := end.Date()
	startYears, startMonths, startDays := start.Date()

	var result = ""

	// Calculate the difference
	years -= startYears
	months -= startMonths
	days -= startDays

	// Handle negative values for months and days
	if months < 0 {
		years--
		months += 12
	}
	if days < 0 {
		months--
		previousMonth := time.Date(end.Year(), end.Month()-1, 1, 0, 0, 0, 0, time.UTC)
		days += previousMonth.AddDate(0, 1, -1).Day()
	}

	// Now calculate hours, minutes
	hours := int(end.Sub(start).Hours()) % 24
	minutes := int(end.Sub(start).Minutes()) % 60

	if years > 0 {
		result += strconv.Itoa(years) + " y, "
	}

	if months > 0 {
		result += months.String() + " m, "
	}

	if days > 0 {
		result += strconv.Itoa(days) + " d, "
	}

	result += strconv.Itoa(hours) + "h, "
	result += strconv.Itoa(minutes) + "mins"

	// Format the output
	return result
}

func Compute_Renewal_Timeline(x509_cert *x509.Certificate) int {
	totalLifetime := x509_cert.NotAfter.Sub(x509_cert.NotBefore).Hours() / 24
	now := time.Now()
	seventyFivePercentDays := totalLifetime * 0.75
	targetDate := x509_cert.NotBefore.Add(time.Duration(seventyFivePercentDays*24) * time.Hour)

	return int(math.Round(targetDate.Sub(now).Hours() / 24))
}
