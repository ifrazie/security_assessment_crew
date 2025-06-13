from crewai import Agent, Crew, Process, Task
from crewai.project import CrewBase, agent, crew, task

from security_assessment_crew.tools.scan_network import ScanNetworkTool
import yaml
import os

# If you want to run a snippet of code before or after the crew starts,
# you can use the @before_kickoff and @after_kickoff decorators
# https://docs.crewai.com/concepts/crews#example-crew-class-with-decorators

@CrewBase
class SecurityToolsCrew():
    """Security Tools Crew"""

    # Learn more about YAML configuration files here:
    # Agents: https://docs.crewai.com/concepts/agents#yaml-configuration-recommended
    # Tasks: https://docs.crewai.com/concepts/tasks#yaml-configuration-recommended
    agents_config = 'config/agents.yaml'
    tasks_config = 'config/tasks.yaml'

    def _load_yaml(self, path):
        if not isinstance(path, str):
            raise TypeError(f"_load_yaml expects a string path, got {type(path).__name__}")
        with open(os.path.join(os.path.dirname(__file__), path), 'r') as f:
            return yaml.safe_load(f)

    # If you would like to add tools to your agents, you can learn more about it here:
    # https://docs.crewai.com/concepts/agents#agent-tools
    @agent
    def cybersecurity_analyst(self) -> Agent:
        agents = self._load_yaml(SecurityToolsCrew.agents_config)
        cfg = agents['cybersecurity_analyst']
        return Agent(
            role=cfg['role'],
            goal=cfg['goal'],
            backstory=cfg['backstory'],
            llm=cfg.get('llm'),
            verbose=True,
            tools=[ScanNetworkTool(result_as_answer=True)] # Example of adding a tool to the agent
        )
    
    @agent
    def technical_analyst(self) -> Agent:
        agents = self._load_yaml(SecurityToolsCrew.agents_config)
        cfg = agents['technical_analyst']
        return Agent(
            role=cfg['role'],
            goal=cfg['goal'],
            backstory=cfg['backstory'],
            llm=cfg.get('llm'),
            verbose=True,
        )

    # To learn more about structured task outputs,
    # task dependencies, and task callbacks, check out the documentation:
    # https://docs.crewai.com/concepts/tasks#overview-of-a-task
    @task
    def scan_ip_task(self) -> Task:
        tasks = self._load_yaml(SecurityToolsCrew.tasks_config)
        cfg = tasks['scan_ip_task']
        return Task(
            description=cfg['description'],
            expected_output=cfg['expected_output'],
            agent=self.cybersecurity_analyst()
        )

    @task
    def create_report_task(self) -> Task:
        tasks = self._load_yaml(SecurityToolsCrew.tasks_config)
        cfg = tasks['create_report_task']
        return Task(
            description=cfg['description'],
            expected_output=cfg['expected_output'],
            agent=self.technical_analyst(),
            context=[self.scan_ip_task()]
        )

    @crew
    def crew(self) -> Crew:
        """Creates the Security crew"""
        return Crew(
            name='SecurityToolsCrew',
            agents=[self.cybersecurity_analyst(), self.technical_analyst()],
            tasks=[self.scan_ip_task(), self.create_report_task()],
            process=Process.sequential,
            verbose=True,
            # process=Process.hierarchical, # In case you wanna use that instead https://docs.crewai.com/how-to/Hierarchical/
        )