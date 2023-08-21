// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import the ZKP-based verifier contract
// import "./verifier.sol";
import "./combinedVerifier.sol";


contract NmrPlatform {
    // Mapping to store the verified status of each user
    mapping(address => bool) public isUserVerified;

    // Mapping to store the roles of each use
    // 0 -> reporter
    // 1 -> managers
    // 2 -> supervisor
    mapping(address => uint) public userRole;
    enum ReportStatus {Accept, Reject, Pending}

    // count the number of reports
     uint256 public reportCount;

      struct IncidentReport {
        uint256 id;
        address reporter;
        string category;
        uint256 dateOfEvent;
        string locationOfEvent;
        string description;
        string title;
        string severity;
        string involvedObject;
        string[] files;
        ReportStatus status;
    }

    mapping(uint256 => IncidentReport) public incidentReports;
    mapping(address => uint256[]) private reportsByReporter;
    
    

    event IncidentReportSubmitted(uint256 indexed reportId, address indexed reporter);
    event IncidentReportStatusChanged(uint256 indexed reportId, ReportStatus newStatus);
    event UserAdded(address indexed userRole, string role);



    // Verifier contract instance
    Verifier verifierInstance;

    // Constructor to initialize the Verifier contract instance
    constructor() {
        verifierInstance = new Verifier();
    }


    // Function to add a new user after verification
    function addUser(Verifier.Proof memory proof, uint role) public returns (bool){
        // Ensure that the sender is verified by the ZKP-based verifier
        require(verifierInstance.verifyTx(proof, role), "User not verified by the ZKP verifier");

        // Mark the user as verified
        isUserVerified[msg.sender] = true;
        // Give role to user
        userRole[msg.sender] = role;

        string memory roleString;

            if (role == 0) {
                roleString = "reporter";
            } else if (role == 1) {
                roleString = "manager";
            } else if (role == 2) {
                roleString = "supervisor";
            }

        // Emit an event to log the user registration
        emit UserAdded(msg.sender, roleString);

        return  isUserVerified[msg.sender];

        
    }

    function checkUser() public view  returns (bool, string memory) {

        bool verified = isUserVerified[msg.sender];
        string memory roleString;

        if (verified) {
            uint role = userRole[msg.sender];
            if (role == 0) {
                roleString = "reporter";
            } else if (role == 1) {
                roleString = "manager";
            } else if (role == 2) {
                roleString = "supervisor";
            }
        }

        return (verified, roleString);
    }

    function submitIncidentReport(string memory category, uint256 dateOfEvent, string memory locationOfEvent, string memory description, string memory title, string memory severity, string memory involvedObjects, string[] memory files) external  {
        require(userRole[msg.sender] == 0, "You are not an authorized reporter!");
        
         reportCount++;
        incidentReports[reportCount] = IncidentReport(reportCount, msg.sender, category, dateOfEvent, locationOfEvent, description, title, severity, involvedObjects, files,  ReportStatus.Pending);
        reportsByReporter[msg.sender].push(reportCount);
        emit IncidentReportSubmitted(reportCount, msg.sender);
    }

    function changeReportStatus(uint256 reportId, ReportStatus newStatus) external  {
        require(incidentReports[reportId].id != 0, "Report does not exist");
        require(userRole[msg.sender] == 2, "You are not authorized to change report status");
        incidentReports[reportId].status = newStatus;
        emit IncidentReportStatusChanged(reportId, newStatus);
    }

      // Function to return all incident reports reported by msg.sender
    function getReportsBySender() external view returns (IncidentReport[] memory) {
         require(isUserVerified[msg.sender] == true, "not authorized to view");
        uint256 totalReports = reportsByReporter[msg.sender].length;
        IncidentReport[] memory senderReports = new IncidentReport[](totalReports);
        for (uint256 i = 0; i < totalReports; i++) {
            senderReports[i] = incidentReports[reportsByReporter[msg.sender][i]];
        }
        return senderReports;
    }

        // Function to return all incident reports
    function getReports() external view returns (IncidentReport[] memory) {
        require(isUserVerified[msg.sender] == true, "not authorized to view");
        IncidentReport[] memory allReports = new IncidentReport[](reportCount);
        for (uint256 i = 1; i <= reportCount; i++) {
            allReports[i - 1] = incidentReports[i];
        }
        return allReports;
    }

    function getAcceptedReports() external view returns (IncidentReport[] memory) {
    uint256 acceptedCount = 0;
    // Count the number of accepted reports
    for (uint256 i = 1; i <= reportCount; i++) {
        if (incidentReports[i].status == ReportStatus.Accept) {
            acceptedCount++;
        }
    }
    // Create an array to store accepted reports
    IncidentReport[] memory acceptedReports = new IncidentReport[](acceptedCount);
    uint256 index = 0;
    // Populate the array with accepted reports
    for (uint256 i = 1; i <= reportCount; i++) {
        if (incidentReports[i].status == ReportStatus.Accept) {
            acceptedReports[index] = incidentReports[i];
            index++;
        }
    }
    return acceptedReports;
    }

} 